
def main():
    with open("tracy-server", "rb") as server_file:
        contents = server_file.read()
        while True:
            search_for = input()
            bytes_to_search_for = bytes([int(search_for[c:c+2], base=16) for c in range(0, len(search_for), 2)])
            index = contents.find(bytes_to_search_for)
            if index != -1:
                print(f"Found {bytes_to_search_for.hex()} at {hex(index)}")
            

if __name__ == "__main__":
    main()
