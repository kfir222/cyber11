num = int(input("Enter a number: "))

if 0 <= num:
    binary = ""
    n = num
    while n > 0:
        binary = str(n % 2) + binary
        n = n // 2
    print(binary)
else:
    print("Number out of range.")
