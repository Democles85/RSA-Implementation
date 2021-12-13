/*
  RSA Encryption & Decryption
  By Sixhei Tartari
  Teacher: Besnik Mehmetaj, CS 378 | UVMS | 2021 December

  Description:  An example of RSA encryption.  Using both public and private keys
to encode a message to cyphertext and decode cyphertext back to the message.  Both
Keys are givin via text file using Hex versions of (e,n) and (d,n) notation.
*/

#include <iostream>
#include <cmath>
#include <string>
#include <fstream>
#include <vector>
using namespace std;

struct key
{
  int x;
  int y;
};
struct table
{
  string value;
  string car;
};

vector<table> AsciiTable;

void loadAscii();
key getPublicKey();
key getPrivateKey();
string enCrypt(string, key);
string deCrypt(string, key);
string toHex(string);
string toChar(string);
string numToHex(int);
string Reverse(string);
double powBig(double, int, int);
double toNum(string);

int main()
{
  loadAscii();
  string originalMsg = "",        // Original Message
      initialMessage = "",        // Message
      message_to_cyphertext = ""; // Cyphertext
  key tKey;

  cout << "Message: ";
  getline(cin, originalMsg);
  // Display Keys
  tKey = getPrivateKey();
  cout << "Private Key = (" << tKey.x << ", " << tKey.y << ")" << endl;
  tKey = getPublicKey();
  cout << "Public Key = (" << tKey.x << ", " << tKey.y << ")" << endl;
  // Encode Message via Private Key
  message_to_cyphertext = enCrypt(originalMsg, getPrivateKey());
  cout << "\nEncoded Message (private key):\n"
       << message_to_cyphertext << endl
       << endl;
  // Decode Message via Public Key
  initialMessage = deCrypt(message_to_cyphertext, getPublicKey());
  cout << "Decoded Message (public key): " << initialMessage << endl;
  // Encode Message via Public Key
  message_to_cyphertext = enCrypt(originalMsg, getPublicKey());
  cout << "\nEncoded Message (public key):\n"
       << message_to_cyphertext << endl
       << endl;
  // Decode Message via Private Key
  initialMessage = deCrypt(message_to_cyphertext, getPrivateKey());
  cout << "Decoded Message (private key): " << initialMessage << endl;

  system("pause");
  return 0;
}

void loadAscii()
{ // Pre: ascii table file contains the hex value and then the character
  // Post: AsciiTable contains the hex value and character
  table temp;
  ifstream ascii;
  ascii.open("ASCII/ascii_table.txt");
  if (!ascii.is_open())
    cout << "Error opening file\n";
  while (!ascii.eof())
  {
    ascii >> temp.value;
    if (temp.value == "20")
      temp.car = ' ';
    else
      ascii >> temp.car;
    AsciiTable.push_back(temp);
  }
  ascii.close();
}

double powBig(double num, int exp, int mod)
{ // Pre: mod != 0
  // Post: Returns num ^ exp % mod, used instead of storing large numbers.
  double sum = num;
  for (int x = exp; x > 1; x--)
  {
    sum = int((num * sum)) % mod;
  }
  return sum;
}

string toHex(string car)
{ // Pre: String contains only 1 character
  // Post: Convert a character in a string to Hex
  string str = "";
  for (int x = 0; x < AsciiTable.size(); x++)
  {
    if (AsciiTable[x].car == car)
    {
      str = AsciiTable[x].value;
    }
  }
  return str;
}

string toChar(string str)
{ // Pre: Contains one hex digit (example 01)
  // Post: Converts a hex digit to a character in the ascii table
  string car = "";
  for (int x = 0; x < AsciiTable.size(); x++)
  {
    if (AsciiTable[x].value == str)
      car = AsciiTable[x].car;
  }
  return car;
}
double toNum(string str)
{ // Pre: Hex letters are Capitol, contains one hex digit
  // Post: Convert a Hex string to a double integer
  double num = 0;
  const char *tempCar;
  string tempStr = "";
  double i = 0.00;
  for (int x = 0; x < str.size(); x++)
  {
    double i = str.size() - (x + 1.0);
    tempStr = str.substr(x, 1);
    tempCar = tempStr.c_str();
    if (isalpha(int(*tempCar)))
      num += (int(*tempCar) - 55) * pow(16.0, i);
    else
      num += (int(*tempCar) - 48) * pow(16.0, i);
  }
  return num;
}

string numToHex(int decimal)
{ // Pre: Passed a decimal number between 0 and 255
  // Post: Returns the converted Hexadecimal number
  string hexNum = ""; // Hexadecimal Number
  int org_decimal = decimal;
  if (decimal == 0)
    hexNum += "0";
  while (decimal > 0) // Converts Decimal to Hexadecimal
  {
    if (decimal % 16 > 9) // 10-16 Displays character A-F
      hexNum += (decimal % 16) + 55;
    else
      hexNum += (decimal % 16) + 48;
    decimal /= 16;
  }
  if (org_decimal < 16) // Adds Leading Zeros
    hexNum += "0";
  return Reverse(hexNum); // Reverses/Returns Hex string
}
string deCrypt(string str, key aKey)
{ // Pre: keys are loaded.
  // Post: Returns a Hex string called the cyphertext
  string cStr = "";
  double firstNum = 0;
  double c = 0;
  double mTemp = 0;
  string strTemp = "";
  string m = "";

  for (int x = 0; x < str.size(); x = x + 4)
  {
    // get first 4 digits
    // convert firstNum to decimal
    firstNum = toNum(str.substr(x, 2));
    // convert c to decimal
    c = toNum(str.substr(x + 2, 2));
    // Decrypt M = c^d % n
    mTemp = powBig(c, aKey.x, aKey.y);
    // Add firstNum
    mTemp += (firstNum * aKey.y);
    // convert m to Hex
    strTemp = numToHex(mTemp);
    m = toChar(strTemp);
    // Add to cString
    cStr += m;
  }

  return cStr;
}
string enCrypt(string str, key aKey)
{ // Pre: Keys are loaded.
  // Post: Returns a string called the message
  string cStr = "";
  string strHex = "";
  double strNum = 0;
  double tempNum = 0;
  double firstNum = 0;
  int c = 0;
  string cHex = "";
  for (int s = 0; s < str.size(); s++)
  {
    // Convert Message to Ascii Hex
    strHex = toHex(str.substr(s, 1));
    // convert hex to decimal
    strNum = toNum(strHex);
    // Ecrypt Begins
    // First Digit (n multiple)
    tempNum = int(strNum) % aKey.y;
    firstNum = (strNum - tempNum) / aKey.y;
    // Encode via C = M^e % n
    c = powBig(tempNum, aKey.x, aKey.y);
    // Convert FirstNum to Hex
    cHex = numToHex(firstNum);
    // Convert c to Hex
    cHex += numToHex(c);
    // Add to encrypted string
    cStr += cHex;
  }
  return cStr;
}

key getPublicKey()
{ // Pre: PublicKey exists in hex e,n
  // Post: aKey = (e,n)
  key aKey;
  string x = "";
  ifstream pubKey;
  pubKey.open("KEYS/PublicKey");
  pubKey >> x;
  aKey.x = toNum(x);
  pubKey >> x;
  aKey.y = toNum(x);
  return aKey;
}

key getPrivateKey()
{ // Pre: Private Key exists in hex d,n
  // Post: aKey = (d,n)
  key aKey;
  string x = "";
  ifstream privKey;
  privKey.open("KEYS/PrivateKey");
  privKey >> x;
  aKey.x = toNum(x);
  privKey >> x;
  aKey.y = toNum(x);
  return aKey;
}

string Reverse(string input)
{ // Pre: none
  // Post: Returns the input string reversed.
  string output = "";
  for (int z = input.size(); z >= 0; z--)
    output += input.substr(z, 1);
  return output;
}

/*
        Sample Output
 Message : Hello I am Democles
 Private Key = (3, 33)
 Public Key = (7, 33)
 Encoded Message(private key) : 0212030803030303030C0020020D00200219030A002002080308030A030C0300030303080304
 Decoded Message(public key) : Hello I am Democles
 Encoded Message(public key) : 021E031D030F030F030C0020021C00200204030A0020021D031D030A030C0300030F031D0319
 Decoded Message(private key) : Hello I am Democles
 */