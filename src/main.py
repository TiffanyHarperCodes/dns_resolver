import argparse
from src.resolver import DNSResolver


def main():
    parser = argparse.ArgumentParser(description="Simple DNS Resolver")
    parser.add_argument("domain", help="Domain name to resolve")
    args = parser.parse_args()

    resolver = DNSResolver()
    response = resolver.resolve(args.domain)

    print(response)


if __name__ == "__main__":
    main()


    