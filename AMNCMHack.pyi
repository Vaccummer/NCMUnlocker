from __future__ import annotations
import typing
__all__ = ['NCMErrorCode', 'NCMUnlocker']
class NCMErrorCode:
    """
    Members:
    
      Success
    
      SrcNotExist
    
      SrcNotFile
    
      DstNotDir
    
      InvalidSrcFormat
    
      InvalidKeySize
    
      InvalidDataSize
    
      EVPContextCreationFailed
    
      KeyInitFailed
    
      AESDecryptionFailed
    
      InvalidCoverFormat
    
      InvalidMusicFormat
    
      OpenSrcFileFailed
    
      OpenDstPathFailed
    
      SaveFileFailed
    
      TaglibError
    
      UnknownError
    """
    AESDecryptionFailed: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.AESDecryptionFailed: -9>
    DstNotDir: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.DstNotDir: -3>
    EVPContextCreationFailed: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.EVPContextCreationFailed: -7>
    InvalidCoverFormat: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.InvalidCoverFormat: -10>
    InvalidDataSize: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.InvalidDataSize: -6>
    InvalidKeySize: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.InvalidKeySize: -5>
    InvalidMusicFormat: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.InvalidMusicFormat: -11>
    InvalidSrcFormat: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.InvalidSrcFormat: -4>
    KeyInitFailed: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.KeyInitFailed: -8>
    OpenDstPathFailed: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.OpenDstPathFailed: -12>
    OpenSrcFileFailed: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.OpenSrcFileFailed: -13>
    SaveFileFailed: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.SaveFileFailed: -14>
    SrcNotExist: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.SrcNotExist: -1>
    SrcNotFile: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.SrcNotFile: -2>
    Success: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.Success: 0>
    TaglibError: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.TaglibError: -15>
    UnknownError: typing.ClassVar[NCMErrorCode]  # value = <NCMErrorCode.UnknownError: -16>
    __members__: typing.ClassVar[dict[str, NCMErrorCode]]  # value = {'Success': <NCMErrorCode.Success: 0>, 'SrcNotExist': <NCMErrorCode.SrcNotExist: -1>, 'SrcNotFile': <NCMErrorCode.SrcNotFile: -2>, 'DstNotDir': <NCMErrorCode.DstNotDir: -3>, 'InvalidSrcFormat': <NCMErrorCode.InvalidSrcFormat: -4>, 'InvalidKeySize': <NCMErrorCode.InvalidKeySize: -5>, 'InvalidDataSize': <NCMErrorCode.InvalidDataSize: -6>, 'EVPContextCreationFailed': <NCMErrorCode.EVPContextCreationFailed: -7>, 'KeyInitFailed': <NCMErrorCode.KeyInitFailed: -8>, 'AESDecryptionFailed': <NCMErrorCode.AESDecryptionFailed: -9>, 'InvalidCoverFormat': <NCMErrorCode.InvalidCoverFormat: -10>, 'InvalidMusicFormat': <NCMErrorCode.InvalidMusicFormat: -11>, 'OpenSrcFileFailed': <NCMErrorCode.OpenSrcFileFailed: -13>, 'OpenDstPathFailed': <NCMErrorCode.OpenDstPathFailed: -12>, 'SaveFileFailed': <NCMErrorCode.SaveFileFailed: -14>, 'TaglibError': <NCMErrorCode.TaglibError: -15>, 'UnknownError': <NCMErrorCode.UnknownError: -16>}
    def __eq__(self, other: typing.Any) -> bool:
        ...
    def __getstate__(self) -> int:
        ...
    def __hash__(self) -> int:
        ...
    def __index__(self) -> int:
        ...
    def __init__(self, value: int) -> None:
        ...
    def __int__(self) -> int:
        ...
    def __ne__(self, other: typing.Any) -> bool:
        ...
    def __repr__(self) -> str:
        ...
    def __setstate__(self, state: int) -> None:
        ...
    def __str__(self) -> str:
        ...
    @property
    def name(self) -> str:
        ...
    @property
    def value(self) -> int:
        ...
class NCMUnlocker:
    def BaseUnlock(self, src: str, dst_dir: str, chunk_size: int = 0) -> NCMErrorCode:
        ...
    def BatchUnlock(self, srcs: list[str], dst_dir: str, chunk_size: int = 0, thread_num: int = 1, cb: typing.Any = None) -> dict[str, NCMErrorCode]:
        ...
    def MapBatchUnlock(self, tasks: list[tuple[str, str]], chunk_size: int = 0, thread_num: int = 1, cb: typing.Any = None) -> dict[str, NCMErrorCode]:
        ...
    def SetHeader(self, header: list[int]) -> None:
        ...
    def __init__(self, core_key: str = '687A4852416D736F356B496E62617857', meta_key: str = '2331346C6A6B5F215C5D2630553C2728') -> None:
        ...
