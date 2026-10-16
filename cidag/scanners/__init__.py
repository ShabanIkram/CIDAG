"""Scanner modules. Importing this package registers every bundled scanner."""
from . import s3  # noqa: F401  (registers "s3")
from . import ec2  # noqa: F401  (registers "ec2")
from . import network  # noqa: F401 (registers "net")
from . import imports  # noqa: F401 (registers import/inspector/sechub)

from .imports import inspector, sechub, files  # noqa: F401

__all__ = ["s3", "ec2", "network", "imports"]
