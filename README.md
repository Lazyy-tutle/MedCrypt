# 📷🔐 MedCrypt

Welcome to the **MedCrypt**! This Streamlit web app lets you encrypt and decrypt images using elliptic curve cryptography (ECC) and pixel shuffling. It's a fun and interactive way to explore cryptography and secure your images! 🚀

## 🎉 Features

- **Upload Images**: Upload your scans in PNG, JPG, or JPEG format.
- **Encrypt Images**: Secure your images with ECC and pixel shuffling.
- **Decrypt Images**: Restore your images to their original form.
- **Interactive Display**: View the original, encrypted, and decrypted images side by side.

## 📦 Installation

To get started with the Image Encryption App, follow these steps:

1. **Clone the Repository**:

    ```sh
    git clone https://github.com/Lazyy-tutle/SWE-ECC.git
    cd SWE-ECC
    ```

2. **Install Dependencies**:

    Make sure you have Python 3.7+ installed. Then, install the required packages:

    ```sh
    pip install -r requirements.txt
    ```

3. **Run the App**:

    Launch the Streamlit app:

    ```sh
    streamlit run app.py
    ```

## 🛠️ Requirements

Here are the main packages you'll need:

- `streamlit==1.22.0`: The web app framework for creating interactive apps.
- `numpy==1.24.3`: For numerical operations and handling image data.
- `Pillow==9.5.0`: For image processing.
- `cryptography==41.0.1`: For encryption and decryption using ECC.
- `matplotlib==3.7.1`: For displaying images (though not used directly in this version, it's handy for image manipulation).

## 🚀 Usage

1. **Open the Web App**:
   - Run the web app using `streamlit run app.py`.
   - Open your browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`).

2. **Encrypt an Image**:
   - Go to the "Image Encryption" page.
   - Upload an image by clicking on "Choose an image...".
   - Watch as the app displays the original, encrypted, and decrypted images!

## 🤔 How It Works

- **Pixel Shuffling**: The app randomly shuffles the pixels of your image to obscure it.
- **ECC Encryption**: The shuffled image data is encrypted using elliptic curve cryptography (ECC) with the NIST P-256 curve.
- **Decryption and Unshuffling**: The encrypted image is decrypted, and the pixels are restored to their original positions.

## 🖼️ Example

Here's a quick example of what you'll see:

![Example Screenshot](Example.png)

## 🤝 Contributing

Got ideas to make this app even cooler? Contributions are welcome! Feel free to fork the repository, make your changes, and submit a pull request.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🎉 Have Fun!

We hope you enjoy using the Image Encryption App. Have fun encrypting and decrypting your images! 😄🔒
