"""Run API: python -m hackon.backend.api"""

from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run("hackon.backend.api.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
