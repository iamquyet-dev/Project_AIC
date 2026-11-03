"""Small manual smoke check for the web prediction core."""

from core import predict_urls


if __name__ == "__main__":
    results = predict_urls(["https://google.com"])
    print("OK:", results[0]["verdict"] if results else "no result")
