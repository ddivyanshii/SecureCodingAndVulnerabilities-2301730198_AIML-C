// Unsecure Solution

#include <iostream>
#include <string>
using namespace std;

int main() {
     // int->short
     // int- integer value (4 bytes)
     // short- smaler integer value (2 bytes)
    int a = 40000; 
    short b = (short)a;
    cout << "int -> short: " << a << " -> " << b << endl;
     // signed->unsigned
     // signed-can store bith negative and positive no.(32 bits)
     // unsigned-ony stores 0, positive no.(32 bits)
    int x = -42;
    unsigned int y = (unsigned int)x;
    cout << "signed -> unsigned: " << x << " -> " << y << endl;
     // float->int 
     // float-decimal no (4 bytes)
     // int-integer value (4 bytes)
    float f = 123.987;
    int i = (int)f;
    cout << "float -> int: " << f << " -> " << i << endl;
     // string->short
     // string-characters written in ""
     // short-smaller integer value(2 bytes)
    string s = "40000";
    short n = (short)stoi(s);
    cout << "string -> short: " << s << " -> " << n << endl;

     return 0;
 }


 // Secure Solution

 #include <iostream>
#include <string>
using namespace std;

int main() {
    int a = 40000;
    if (a >= -32768 && a <= 32767)
        cout << "int -> short: " << (short)a << endl;
    else
        cout << "int -> short: Rejected" << endl;

    int x = -42;
    if (x >= 0)
        cout << "signed -> unsigned: " << (unsigned)x << endl;
    else
        cout << "signed -> unsigned: Rejected" << endl;

    float f = 123.987;
    if (f >= -2147483648.0 && f <= 2147483647.0)
        cout << "float -> int: " << (int)f << endl;
    else
        cout << "float -> int: Rejected" << endl;

    string s = "40000";
    try {
        int n = stoi(s);
        if (n >= -32768 && n <= 32767)
            cout << "string -> short: " << (short)n << endl;
        else
            cout << "string -> short: Rejected" << endl;
    }
    catch (...) {
        cout << "string -> short: Invalid" << endl;
    }

    return 0;
}