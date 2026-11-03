"""Entry point for the pipeline from the project root."""

import runpy


if __name__ == "__main__":
    runpy.run_module("steps.run_all", run_name="__main__")
