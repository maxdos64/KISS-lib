#include "compress.h"
#include <iostream>
#include <string>
#include <algorithm>

using namespace std;

int main()
{
	CDatabase db(string("./libc"), string("result"));

	db.GenerateDatabaseToFile();
	db.ConstructFromFile();
}
