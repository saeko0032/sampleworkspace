# sampleworkspace

## プロジェクトの説明

このプロジェクトは、Windows 64ビット環境向けにC++で書かれたコンソールアプリケーションです。Cryptography API: Next Generation (CNG) を使用してRSA暗号化と復号化を実装しています。プロジェクトには、RSAキーを安全に保管および取得し、任意のリストを暗号化および復号化する機能が含まれています。

## ビルドと実行の手順

1. リポジトリをクローンします:
   ```
   git clone https://github.com/saeko0032/sampleworkspace.git
   cd sampleworkspace
   ```

2. お好みのC++開発環境（例：Visual Studio）でプロジェクトを開きます。

3. プロジェクトをビルドします:
   - 必要なWindows SDKがインストールされていることを確認します。
   - ソリューションをビルドして実行ファイルを生成します。

4. 実行ファイルを実行します:
   - 出力ディレクトリ（例：`Debug` または `Release`）に移動します。
   - 生成された実行ファイル（例：`sampleworkspace.exe`）を実行します。

## 使用方法

1. RSAキーの生成またはインポート:
   - アプリケーションはRSAキーを生成またはインポートし、Windows Data Protection API (DPAPI) を使用して安全に保管します。

2. データの暗号化:
   - 提供された機能を使用して、公開鍵でデータを暗号化します。

3. データの復号化:
   - 提供された機能を使用して、秘密鍵でデータを復号化します。

4. 任意のリストの暗号化と復号化:
   - アプリケーションには、実装されたRSA暗号化および復号化機能を使用して任意のリストを暗号化および復号化する機能が含まれています。

## CMakeを使用したビルド手順

このプロジェクトはCMakeを使用してビルドすることもできます。以下の手順に従ってください。

### 必要条件

- CMake 3.10以上がインストールされていることを確認してください。

### ビルド手順

1. リポジトリをクローンします:
   ```
   git clone https://github.com/saeko0032/sampleworkspace.git
   cd sampleworkspace
   ```

2. vcpkgをインストールします:
   ```
   git clone https://github.com/microsoft/vcpkg.git
   cd vcpkg
   ./bootstrap-vcpkg.bat
   ```

3. vcpkgをCMakeに統合します:
   ```
   ./vcpkg integrate install
   ```

4. ビルドディレクトリを作成して移動します:
   ```
   mkdir build
   cd build
   ```

5. CMakeを使用してビルドファイルを生成します:
   ```
   cmake -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake -A x64 ..
   ```

6. プロジェクトをビルドします:
   ```
   cmake --build .
   ```

7. 実行ファイルを実行します:
   - 出力ディレクトリ（例：`Debug` または `Release`）に移動します。
   - 生成された実行ファイル（例：`sampleworkspace.exe`）を実行します。
