# test.py

# 🔴 Vulnerable: unsafe use of eval
user_input = "2+2"
print("Result of eval:", eval(user_input))

# 🟢 Safe: normal math operation
x = 10
y = 20
print("Safe addition:", x + y)

# 🔴 Vulnerable: eval with user-supplied string
data = input("Enter something: ")
print(eval(data))  # This is very unsafe!

# 🟢 Safe: using int() parsing instead of eval
num = input("Enter a number: ")
try:
    num = int(num)
    print("Safe number input:", num)
except ValueError:
    print("Not a valid number")
