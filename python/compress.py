import kisslib


def main():
    db = DatabaseInstance("../static", "result")
    db.generate_database_to_file()
    db.construct_from_file()

if __name__ == "__main__":
    main()
