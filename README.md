# 🧠 Pametni sistem za nadzor omrežnega prometa

Ta Python aplikacija z grafičnim vmesnikom omogoča **nadzor in klasifikacijo omrežnega prometa** s pomočjo **strojnega učenja**. Podpira tako **realni zajem prometa** preko Scapy kot tudi **simulacijo prometa**, beleži dogodke in podatke prikazuje v obliki grafov.

---

## 📦 Funkcionalnosti

- 🧪 Uporaba ML modela **Random Forest**, treniranega na [UNSW-NB15 podatkovnem naboru](#podatkovni-nabor)
- 🌐 Podpora za **realni zajem** in **simulacijo prometa**
- 📊 Živa vizualizacija s pomočjo grafov
- 📋 Kategorizirano beleženje (Model, Pravilo, Informacija)
- 🖥️ Uporabniku prijazen grafični vmesnik (Tkinter)

---

## 📁 Podatkovni nabor

Za pravilno delovanje moraš prenesti **UNSW-NB15 (CSV)** podatke:

👉 [Prenesi CSV datoteke – UNSW-NB15 (podatkovna nabora za treniranje modela in testiranje)](https://unsw-my.sharepoint.com/personal/z5025758_ad_unsw_edu_au/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Fz5025758%5Fad%5Funsw%5Fedu%5Fau%2FDocuments%2FUNSW%2DNB15%20dataset%2FCSV%20Files%2FTraining%20and%20Testing%20Sets&ga=1)

1. Ustvari mapo z imenom `unsw/` v glavni mapi projekta.
2. Vanjo postavi naslednji datoteki:
   - `UNSW_NB15_training-set.csv`
   - `UNSW_NB15_testing-set.csv`

---

## 🚀 Zagon aplikacije

### ✅ Zahteve

- Python 3.x
- Potrebne knjižnice:
  ```bash
  pip install scapy pandas numpy matplotlib scikit-learn
