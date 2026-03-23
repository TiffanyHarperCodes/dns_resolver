import argparse # Python built-in library for handling command line arguments
from src.resolver import DNSResolver
import logging

logging.basicConfig(level=logging.DEBUG)


def main():
    parser = argparse.ArgumentParser(description="DNS Resolver")
    parser.add_argument("domain", help="Domain name to resolve")
    args = parser.parse_args()

    resolver = DNSResolver()
    response = resolver.resolve(args.domain)

    print(response)


if __name__ == "__main__":
    main()


    