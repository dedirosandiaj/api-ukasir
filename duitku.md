Get Payment Method
Proses ini digunakan untuk mendapatkan metode pembayaran yang aktif dari proyek merchant (anda). API ini berisi nama metode pembayaran, biaya dan URL ke gambar metode pembayaran. Anda dapat menggunakan sebagai daftar channel pembayaran pada proyek anda dan anda akan mendapatkan paymentMethod yang berguna untuk diteruskan ke proses request transaksi. Proses ini opsional, anda dapat melewatinya menuju Permintaan Transaksi.

Request HTTP Get Payment Method
Method : HTTP POST

Type : application/json

Development : https://sandbox.duitku.com/webapi/api/merchant/paymentmethod/getpaymentmethod

Production : https://passport.duitku.com/webapi/api/merchant/paymentmethod/getpaymentmethod

Parameter Request Get Payment Method
curl -X POST https://sandbox.duitku.com/webapi/api/merchant/paymentmethod/getpaymentmethod
-H "Content-Type: application/json"
-d "{
    \"merchantcode\": \"DXXXX\",
    \"amount\": \"10000\",
    \"datetime\": \"2022-01-25 16:23:08\",
    \"signature\": \"497fbf783f6d17d4b1e1ef468917bdc8\"
    }"
Nama	Tipe	Wajib	Keterangan	Contoh
merchantcode	string(50)	
✓

Kode merchant dari duitku.	DXXXX
amount	integer	
✓

Nominal transaksi. Tidak ada kode desimal (.) dan tidak ada digit desimal.	10000
datetime	date	
✓

Format: (yyyy-MM-dd HH:mm:ss).	2022-01-25 16:23:08
signature	string(255)	
✓

Formula :
stringToSign = merchantcode + paymentAmount + datetime
signature = HMAC_SHA256(stringToSign, apiKey)	d842db69f70501fe69487b3d957
611c2d4e47335f390a5895b0a762a1bf1f1a0
Note
Metode signature sebelumnya yang menggunakan SHA256 sudah usang (obsolete).
Parameter Respon Get Payment Method
Type : application/json

{
    "paymentFee": [        
        {
            "paymentMethod": "VA",
            "paymentName": "MAYBANK VA",
            "paymentImage": "https://images.duitku.com/hotlink-ok/VA.PNG",
            "totalFee": "0"
        },
        {
            "paymentMethod": "BT",
            "paymentName": "PERMATA VA",
            "paymentImage": "https://images.duitku.com/hotlink-ok/PERMATA.PNG",
            "totalFee": "0"
        },
    ],
    "responseCode": "00",
    "responseMessage": "SUCCESS"
}
Nama	Tipe	Keterangan
paymentFee	paymentFee	Berisikan daftar pembayaran.
responseCode	string	Kode respon.
responseMessage	string	Keterangan hasil dari respon.
Permintaan Transaksi
Berikut ini adalah langkah utama pada proses transaksi diawali dengan melakukan request transaksi ke sistem Duitku. Proses ini akan diperuntukan untuk membuat pembayaran (melalui nomor virtual account, QRIS, e-wallet, dsb). Anda dapat membuat suatu halaman pembayaran yang berguna mengarahkan pelanggan membayar tagihan transaksinya kepada anda. Silahkan untuk membuat request transaksi dengan membuat HTTP request seperti berikut. Jika anda melewati Get Payment Method, anda dapat mengisi paymentMethod dengan referensi Metode Pembayaran.

Request HTTP Transaksi
Method : HTTP POST

Type : application/json

Development : https://sandbox.duitku.com/webapi/api/merchant/v2/inquiry

Production : https://passport.duitku.com/webapi/api/merchant/v2/inquiry

Parameter Request Transaksi
curl --location --request POST 'https://sandbox.duitku.com/webapi/api/merchant/v2/inquiry' \
--header 'Content-Type: application/json' \
--data 
'{ 
   "merchantCode":"DXXXX",
   "paymentAmount":40000,
   "paymentMethod":"VC",
   "merchantOrderId":"abcde12345",
   "productDetails":"Pembayaran untuk Toko Contoh",
   "additionalParam":"",
   "merchantUserInfo":"",
   "customerVaName":"John Doe",
   "email":"test@test.com",
   "phoneNumber":"08123456789",
   "itemDetails":[ 
      { 
         "name":"Test Item 1",
         "price":10000,
         "quantity":1
      },
      { 
         "name":"Test Item 2",
         "price":30000,
         "quantity":3
      }
   ],
   "customerDetail":{ 
      "firstName":"John",
      "lastName":"Doe",
      "email":"test@test.com",
      "phoneNumber":"08123456789",
      "billingAddress":{ 
         "firstName":"John",
         "lastName":"Doe",
         "address":"Jl. Kembangan Raya",
         "city":"Jakarta",
         "postalCode":"11530",
         "phone":"08123456789",
         "countryCode":"ID"
      },
      "shippingAddress":{ 
         "firstName":"John",
         "lastName":"Doe",
         "address":"Jl. Kembangan Raya",
         "city":"Jakarta",
         "postalCode":"11530",
         "phone":"08123456789",
         "countryCode":"ID"
      }
   },
   "callbackUrl":"http:\/\/example.com\/callback",
   "returnUrl":"http:\/\/example.com\/return",
   "signature":"d842db69f70501fe69487b3d957611c2d4e47335f390a5895b0a762a1bf1f1a0",
   "expiryPeriod":10
}

Parameter	Tipe	Wajib	Keterangan	Contoh
merchantCode	string(50)	
✓

Kode merchant, adalah kode proyek untuk bertransaksi.	DXXXX
paymentAmount	integer	
✓

Jumlah nominal transaksi.	40000
merchantOrderId	string(50)	
✓

Nomor transaksi dari merchant.	abcde12345
productDetails	string(255)	
✓

Keterangan produk/jasa yang diperjual belikan.	Pembayaran untuk Toko Contoh
email	string(255)	
✓

Alamat email pelanggan anda.	pelanggan_anda@email.com
additionalParam	string(255)	
✗

Parameter tambahan (opsional).	
paymentMethod	string(2)	
✓

Kode metode pembayaran yang digunakan.	VC
merchantUserInfo	string(255)	
✗

Username atau email pelanggan di situs merchant (opsional).	
customerVaName	string(20)	
✓

Nama yang akan muncul pada halaman konfirmasi pembayaran bank.	John Doe
phoneNumber	string(50)	
✗

Nomor telepon pelanggan (opsional).	08123456789
itemDetails	ItemDetails	
✗

Detail barang (opsional).	
customerDetail	CustomerDetail	
✗

Detail pelanggan.	
returnUrl	string(255)	
✓

Tautan untuk mengarahkan setelah transaksi selesai atau dibatalkan.	http://www.contoh.com/return
callbackUrl	string(255)	
✓

Tautan untuk callback transaksi.	http://www.contoh.com/callback
signature	string(255)	
✓

Kode identifikasi transaksi.
Formula :
stringToSign = merchantCode + merchantOrderId + paymentAmount
signature = HMAC_SHA256(stringToSign, apiKey).	d842db69f70501fe69487b3d957
611c2d4e47335f390a5895b0a762a1bf1f1a0
expiryPeriod	int	
✗

Masa berlaku transaksi sebelum kedaluwarsa. Berbentuk satuan angka dalam menit. Untuk detail expiryPeriod bisa dilihat disini.	10
accountLink	AccountLink	
✗

Detail parameter untuk metode pembayaran accountlink (opsional).	
creditCardDetail	creditCardDetail	
✗

Detail parameter untuk pembayaran kartu kredit (opsional).	
 Berikut ini yang dapat anda lakukan:
productDetails dapat anda isikan dengan keterangan produk barang atau jasa yang anda sediakan. Anda juga dapat menyisipkan nama toko atau merek anda untuk lebih jelasnya. Lalu, pada itemDetails sebagai contohnya dapat anda isi variant dari produk atau detail model produk, dan hal lainnya yang mendetail tentang produk/jasa yang tercantum pada transaksi tersebut.
Pastikan nominal paymentAmount setara dengan jumlah dari nominal itemDetails yang ada.
merchantOrderId adalah ID transaksi yang terdapat di setiap request transaksi. Setiap request untuk transaksi baru harus menggunakan ID yang baru.
Jika anda menggunakan additionalParam, mohon pastikan parameter yang anda kirim di dalamnya berbentuk URL encode.
Note
Metode signature sebelumnya yang menggunakan MD5 sudah usang (obsolete).
Fixed VA
Fixed Virtual Account adalah nomor virtual account yang dapat dikustomisasi oleh merchant sehingga menjadi statik atau sesuai dengan keinginan mereka. Merchant dapat menyesuaikan nomor ini setelah angka prefix VA yang diberikan oleh Duitku. Dengan syarat bahwa angka yang ditambahkan tidak melebihi panjang digit maksimal untuk nomor VA tersebut.

Untuk integrasi menggunakan Fixed Virtual Account anda dapat menggunakan API SNAP kami, untuk melihat dokumentasi nya klik disini.

OVO H2H
 Untuk dokumentasi pembayaran via OVO tanpa redirect ke halaman pembayaran duitku, dapat dilihat di sini.
Parameter Respon Request Transaksi
Setelah request transaksi ke API Duitku. Server Duitku akan memberikan respon. Respon ini dapat anda jadikan sebagai data pembayaran untuk pelanggan anda.

{
  "merchantCode": "DXXXX",
  "reference": "DXXXXCX80TZJ85Q70QCI",
  "paymentUrl": "https://sandbox.duitku.com/topup/topupdirectv2.aspx?ref=BCA7WZ7EIDXXXXWEC",
  "vaNumber": "7007014001444348",
  "qrString": "00020101021226660014ID.DANA.WWW011893600911002151500102152006170915150010303UME51450015ID.OR.GPNQR.WWW02150000000000000000303UME520454995802ID5911Toko Jualan6013Jakarta Barat61051153062210117LQKI2LPMJQPKCIIS553033605405400006304502A",
  "AppUrl": "https://tokopedia.app.link/?$ios_deeplink_path=tokopedia%3A%2F%2Fdigital%2Fcart%3Fcategory_id%3dXXXX%26operator_id%3d33334%26product_id%3d77778%26client_number%3d1070026818117867&$android_deeplink_path=tokopedia%3A%2F%2Fdigital%2Fcart%3Fcategory_id%3dXXXX%26operator_id%3d33334%26product_id%3d77778%26client_number%3d1070026818117867&$desktop_url=https%3A%2F%2Fpulsa.tokopedia.com%3Faction%3dinit_data%26category_id%3dXXXX%26operator_id%3d33334%26product_id%3d77778%26client_number%3d1070026818117867",
  "amount": "40000",
  "statusCode": "00",
  "statusMessage": "SUCCESS"
}
Parameter	Tipe	Keterangan	Contoh
merchantCode	string(50)	Kode merchant, kode proyek anda yang dikembalikan dari server Duitku. Menandakan proyek mana yang anda gunakan dalam transaksi.	DXXXX
reference	string(255)	Referensi dari Duitku (perlu disimpan di sistem anda).	DXXXXCX80TXXX5Q70QCI
paymentUrl	string(255)	Tautan halaman pembayaran jika ingin menggunakan halaman Duitku.	https://sandbox.duitku.com/topup/topupdirectv2.aspx?ref=BCA7WZ7EIDXXX7WEC
vaNumber	string(20)	Nomor pembayaran atau virtual account.	7007014001444348
amount	integer	Nominal pembayaran.	40000
qrString	string(255)	QR string digunakan jika anda menggunakan pembayaran QRIS (anda perlu membuat kode QR dari string ini).	
appUrl	string	Tautan halaman pembayaran untuk menuju aplikasi pembayaran e-commerce.	
 Parameter reference perlu anda simpan untuk membantu melakukan pengecekan transaksi di Duitku. Anda dapat mengarahkan pelanggan ke halaman pembayaran dengan menggunakan URL dari parameter paymentUrl. Jika anda memiliki tampilan pembayaran sendiri, anda dapat menggunakan parameter lainnya seperti berikut ini:
vaNumber berisikan nomor virtual account bank untuk pembayaran pelanggan anda nanti. Anda dapat menampilkan VA tersebut untuk mengarahkan pelanggan membayar.
Jika metode pembayaran menggunakan menggunakan QR, anda dapat menggunakan qrString dengan mengubah string tersebut menjadi gambar QR dan ditampilkan pada halaman pembayaran anda.
appUrl dapat digunakan untuk mengarahkan pengguna langsung ke aplikasi e-commerce dari halaman pembayaran Anda.
Callback
curl --location --request POST 'http:\/\/example.com\/callback' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'merchantOrderId=abcde12345' \
--data-urlencode 'amount=150000' \
--data-urlencode 'merchantCode=DXXXX' \
--data-urlencode 'productDetails=Pembayaran untuk Toko Contoh' \
--data-urlencode 'additionalParam=contoh param' \
--data-urlencode 'paymentCode=VA' \
--data-urlencode 'resultCode=00' \
--data-urlencode 'merchantUserId=test@example.com' \
--data-urlencode 'reference=DXXXXCX80TXXX5Q70QCI' \
--data-urlencode 'signature=d842db69f70501fe69487b3d957611c2d4e47335f390a5895b0a762a1bf1f1a0'\
--data-urlencode 'publisherOrderId=MGUHWKJX3M1KMSQN5'\
--data-urlencode 'spUserHash=xxxyyyzzz'\
--data-urlencode 'settlementDate=2023-07-25'\
--data-urlencode 'issuerCode=93600523'\
--data-urlencode 'customerName=Bam**** Maul***'
Parameter callbackUrl yang berada di transaksi request akan digunakan oleh Duitku untuk konfirmasi pembayaran yang telah dilakukan oleh pelanggan anda. Pada saat pelanggan anda berhasil melakukan pembayaran, Duitku akan mengirimkan HTTP POST yang menyertakan hasil pembayaran suatu tagihan dari pelanggan. Anda perlu menyediakan halaman untuk menerima request callback tersebut. Agar dapat memproses hasil transaksi yang telah dilakukan oleh pelanggan.

 Silahkan untuk menambahkan IP outgoing Duitku berikut untuk kebutuhan whitelist.

Production : 182.23.85.8, 182.23.85.9, 182.23.85.10, 182.23.85.13, 182.23.85.14, 103.177.101.184, 103.177.101.185, 103.177.101.186, 103.177.101.189, 103.177.101.190

Sandbox : 182.23.85.11, 182.23.85.12, 103.177.101.187, 103.177.101.188
 Requirements:
PORT: 80 atau 443
URL: Harus dapat diakses secara publik
POST Response: Mengembalikan HTTP 200 OK
Parameter Callback
Method : HTTP POST

Type : x-www-form-urlencoded

Parameter	Keterangan	Contoh
merchantCode	Kode merchant, dikirimkan oleh server Duitku untuk memberitahu kode proyek yang digunakan.	DXXXX
amount	Jumlah nominal transaksi.	150000
merchantOrderId	Nomor transaksi dari merchant.	abcde12345
productDetail	Keterangan detail produk.	Pembayaran untuk Toko Contoh
additionalParam	Parameter tambahan yang anda kirimkan pada saat awal request transaksi.	
paymentCode	Metode Pembayaran.	VC
resultCode	Pemberitahuan callback hasil transaksi.
00 - Success
01 - Failed	00
merchantUserId	Username atau email pelanggan di situs anda.	test@example.com
reference	Nomor referensi transaksi dari Duitku. Mohon disimpan untuk keperluan pencatatan atau pelacakan transaksi.	DXXXXCX80TXXX5Q70QCI
signature	Kode identifikasi transaksi. Berisikan parameter keamanan sebagai acuan bahwa request yang diterima berasal dari server Duitku. Signature dihasilkan menggunakan metode HMAC SHA256.
Formula :
stringToSign = merchantcode + amount + merchantOrderId
signature = HMAC_SHA256(stringToSign, apiKey).	d842db69f70501fe69487b3d957
611c2d4e47335f390a5895b0a762a1bf1f1a0
publisherOrderId	Nomor unik pembayaran transaksi dari Duitku. Mohon disimpan untuk keperluan pencatatan atau pelacakan transaksi.	MGUHWKJX3M1KMSQN5
spUserHash	Di kirim melalui callback jika pembayaran menggunakan metode pembayaran ShopeePay(QRIS, App, dan Account Link). Jika berisi string dengan kombinasi angka dan huruf, maka menandakan pembayaran menggunakan Shopee itu sendiri.	xxxyyyzzz
settlementDate	Informasi waktu estimasi penyelesaian.
Format: YYYY-MM-DD	2023-07-25
issuerCode	Informasi kode issuer dari QRIS.
lihat daftar issuer disini.	93600523
customerName	Pengidentifikasi akun issuer QRIS. Tergantung pada issuer-nya, nilainya dapat berupa nama akun atau nomor telepon. Nilai yang dikembalikan mungkin sebagian disembunyikan.	Bam**** Maul***
 Note
Untuk cek callback anda, dapat menggunakan contoh kode shell untuk melakukan request nya. Sementara itu, jika anda ingin mencoba menerima callback dari server kami, anda mungkin memerlukan URL publik yang dapat diakses melalui internet. Server kami akan mengirim ulang callback jika server belum menangkap HTTP 200. Ketika callback telah dikirim pada upaya maksimum(5 kali), server kami akan mengirimkan pemberitahuan callback gagal melalui email Anda. Anda dapat mengirimkan ulang callback melalui fitur resend yang ada di menu report dashboard duitku.
Note
Metode signature sebelumnya yang menggunakan MD5 sudah usang (obsolete).
Redirect
Pada saat mengirimkan transaksi request bersamaan dengan parameter callbackUrl, anda juga mengirimkan parameter returnUrl. Berbeda dengan callback yang berguna untuk menerima status pembayaran yang dilakukan pelanggan. Redirect berguna pada saat setelah anda mengarahkan pelanggan ke paymentUrl pelanggan akan diarahkan kembali ke situs atau halaman toko anda. Setelah transaksi berhasil atau dibatalkan, Duitku akan mengarahkan pelanggan kembali ke situs anda menggunakan URL beserta parameter berikut.

Contoh

GET: http://www.merchantweb.com/redirect.php?merchantOrderId=abcde12345&resultCode=00&reference=DXXXXCX80TXXX5Q70QCI

Parameters

Parameter	Keterangan	Contoh
merchantOrderId	Nomor transaksi dari merchant.	abcde12345
reference	Nomor referensi transaksi dari Duitku.	DXXXXCX80TXXX5Q70QCI
resultCode	Kode hasil dari transaksi.
00 - Success
01 - Pending
02 - Canceled	00
 Jangan menggunakan resultCode untuk mengupdate status pembayaran di aplikasi atau website anda. Anda dapat menggunakan parameter sebagai dasar informasi pembayaran. Mohon untuk diperhatikan URL dapat diubah secara manual oleh pelanggan.