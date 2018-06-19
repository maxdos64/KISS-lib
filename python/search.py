import kisslib

def main():
    engine = SearchEngine("result.cdb", "result.ofst")

    query = b"\x41\x56\x41\x55\x49\x89\xd6\x41\x54\x55\x49\x89\xf4\x53\x48\x89"
    print("search resulted in {} matches".format(engine.search(bytes(query))))
    result = engine.get_locations(10)
    for r in result:
        print(r)

if __name__ == "__main__":
    main()
