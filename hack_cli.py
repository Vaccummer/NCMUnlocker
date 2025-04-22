import NCMUnlocker
from functools import partial
import argparse
import sys
import os
import re
from tqdm import tqdm


def trace_cb(
    src: str,
    ec: NCMUnlocker.NCMErrorCode,
    success: int,
    failed: int,
    total: int,
    bar_f: tqdm,
):
    bar_f.update(1)
    prompt_f = f"✅ {success}, ❌ {failed}"
    bar_f.set_description(prompt_f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NCM Unlocker CLI")
    parser.add_argument("srcs", type=str, nargs="+", help="Source file or directory")
    parser.add_argument(
        "-t", "--thread", type=int, required=False, help="Thread number"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", required=False, help="Quiet mode"
    )
    parser.add_argument("-o", type=str, required=False, help="Output directory")
    parser.add_argument(
        "-r", action="store_true", required=False, help="Use regex to match filename"
    )
    args = parser.parse_args()
    tar_paths = []
    if args.r:
        for src in args.srcs:
            dir_path = os.path.dirname(src)
            name_pattern = os.path.basename(src)
            try:
                pattern_f = re.compile(name_pattern)
            except re.error:
                print(f"❌ NCMUnlocker: Invalid regex pattern: {name_pattern}")
                sys.exit(1)
            if not os.path.exists(dir_path):
                continue
            for file in os.listdir(dir_path):
                if re.match(pattern_f, file):
                    tar_paths.append(os.path.join(dir_path, file))
    else:
        for src in args.srcs:
            if os.path.isfile(src) and src.endswith(".ncm"):
                tar_paths.append(src)
            elif os.path.isdir(src):
                for file in os.listdir(src):
                    if os.path.isfile(os.path.join(src, file)) and file.endswith(
                        ".ncm"
                    ):
                        tar_paths.append(os.path.join(src, file))

    if not tar_paths:
        print("❌ NCMUnlocker: No NCM files found")
        sys.exit(2)

    thread_num = args.thread or 1
    thread_num = max(1, min(thread_num, 16))

    if not args.quiet:
        tdqm_bar = tqdm(desc="Decrypting", unit="files", total=len(tar_paths))
        trace_need = True
    else:
        tdqm_bar = None
        trace_need = False

    if args.o:
        tar_para = [(p, args.o) for p in tar_paths]
    else:
        tar_para = [(p, os.path.dirname(p)) for p in tar_paths]

    ncm_unlocker = NCMUnlocker.NCMUnlocker()
    trace_n = partial(trace_cb, bar_f=tdqm_bar) if not args.quiet else None

    results = ncm_unlocker.MapBatchUnlock(
        tar_para,
        chunk_size=8192,
        thread_num=thread_num,
        cb=trace_n,
    )

    success_num = sum(
        1 for ec in results.values() if ec == NCMUnlocker.NCMErrorCode.Success
    )
    failed_num = sum(
        1 for ec in results.values() if ec != NCMUnlocker.NCMErrorCode.Success
    )
    if tdqm_bar is not None:
        tdqm_bar.close()

    if not args.quiet:
        for src, ec in results.items():
            if ec != NCMUnlocker.NCMErrorCode.Success:
                print(f"❌ NCMUnlocker: {src} decryption failed, error code: {ec}")

    print(f"NCMUnlocker: Total: {len(results)} , ✅: {success_num} , ❌: {failed_num}")
