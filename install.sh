git clone https://github.com/simongog/sdsl-lite.git sdsl-lite
git pull
cd sdsl-lite
sed -i '1s/^/set(CMAKE_POSITION_INDEPENDENT_CODE ON) # PATCHED IN/' CMakeLists.txt
./install.sh ..
cd ..
git clone https://github.com/serge1/ELFIO.git elfio-lib
git pull
cd elfio-lib
cp -R elfio ../include
cd ..

