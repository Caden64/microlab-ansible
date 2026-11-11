"""Path normalisation matching Technitium's settings serialisation.

Technitium stores ``dnsTlsCertificatePath`` relative to its configuration
folder when the file is inside that folder (``DnsServerCore/LogManager.cs``
``ConvertToRelativePath``), and returns that relative form from
``/api/settings/get``.  Feeding an absolute PFX path back into the settings API
therefore never compares equal to the stored value and produces perpetual
drift.  Normalising both the desired and the read-back path keeps the role
idempotent while still accepting absolute paths outside the config folder.
"""

from __future__ import annotations

import os
from typing import Any, Dict


def technitium_api_path(path: Any, config_dir: Any) -> str:
    """Return the path exactly as Technitium would store it.

    Relative inputs are interpreted relative to ``config_dir`` (Technitium's
    ``ConvertToAbsolutePath`` does the same).  Paths inside the configuration
    folder become relative with forward slashes; paths outside stay absolute.
    """

    if path is None:
        return ""
    path_text = str(path).strip()
    if not path_text:
        return ""
    config_text = str(config_dir).strip()
    if not config_text:
        return path_text

    if not os.path.isabs(path_text):
        path_text = os.path.join(config_text, path_text)

    absolute = os.path.abspath(path_text)
    config_absolute = os.path.abspath(config_text)

    if absolute == config_absolute:
        return absolute

    try:
        relative = os.path.relpath(absolute, config_absolute)
    except ValueError:
        return absolute

    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return absolute
    return relative.replace(os.sep, "/")


class FilterModule:
    def filters(self) -> Dict[str, Any]:
        return {"technitium_api_path": technitium_api_path}
