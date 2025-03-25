#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

using namespace std;

int encryptCharacter(char c) {
    int asciiValue = static_cast<int>(c);
    int sum = 0;

    while (asciiValue > 0) {
        int digit = asciiValue % 10;
        asciiValue /= 10;
        sum += digit;
    }

    return sum;
}

int encryptString(const string& input) {
    int totalSum = 0;

    for (char c : input) {
        totalSum += encryptCharacter(c);
    }

    return totalSum;
}

int main() {
    string input;
    string filename;

    cout << "请输入要加密的内容: ";
    getline(cin, input);

    cout << "请输入保存加密结果的文件名: ";
    cin >> filename;

    int encryptedResult = encryptString(input);

    ofstream outFile(filename);
    if (outFile.is_open()) {
        outFile << "加密结果: " << encryptedResult << endl;
        outFile.close();
        cout << "加密结果已保存到 " << filename << endl;
    } else {
        cerr << "错误: 无法打开文件进行写入。" << endl;
    }

    return 0;
}
