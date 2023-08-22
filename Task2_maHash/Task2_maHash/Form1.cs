using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using static Org.BouncyCastle;


namespace Task2_maHash
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        MD5 md = MD5.Create();


        //ma hoa MD5
        public void maHoaMD5()
        {
            byte[] inpString = System.Text.Encoding.ASCII.GetBytes(textBox1.Text);
            byte[] hash = md.ComputeHash(inpString);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("x2"));
            }
            textBox2.Text = sb.ToString();
        }

        //ma hoa SHA1
        public string maHoaSHA1(string text)
        {
            SHA1CryptoServiceProvider sh = new SHA1CryptoServiceProvider();
            sh.ComputeHash(ASCIIEncoding.ASCII.GetBytes(text));
            byte[] re = sh.Hash;
            StringBuilder sb = new StringBuilder();
            foreach (byte b in re)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        public string convert_NTLM(string ntlm)
        {

            Org.BouncyCastle.Crypto.Digests.MD4Digest md = new Org.BouncyCastle.Crypto.Digests.MD4Digest();

            byte[] unicodePassword = Encoding.Convert(Encoding.ASCII, Encoding.Unicode, Encoding.ASCII.GetBytes(ntlm));


            byte[] hash = new byte[16];
            md.DoFinal(hash, 0);
            return ntlm = BitConverter.ToString(hash);
        }


        //ma hoa SHA256
        public string maHoaSHA256(string text)
        {
            string hash = String.Empty;
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashValue = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
                foreach (byte b in hashValue)
                {
                    hash += $"{b:x2}";
                }
            }
            return hash;
        }
        //ma hoa NTLM
        public static string Ntlm(string key)
        {
            const uint INIT_A = 0x67452301;
            const uint INIT_B = 0xefcdab89;
            const uint INIT_C = 0x98badcfe;
            const uint INIT_D = 0x10325476;

            const uint SQRT_2 = 0x5a827999;
            const uint SQRT_3 = 0x6ed9eba1;

            char[] itoa16 = new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

            uint[] nt_buffer = new uint[16];
            uint[] output = new uint[4];
            char[] hex_format = new char[32];

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // Prepare the string for hash calculation
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            int i = 0;
            int length = key.Length;
            //The length of key need to be <= 27
            for (; i < length / 2; i++)
            {
                nt_buffer[i] = (key[2 * i] | ((uint)key[2 * i + 1] << 16));
            }

            //padding
            if (length % 2 == 1)
            {
                nt_buffer[i] = (uint)key[length - 1] | 0x800000;
            }
            else
            {
                nt_buffer[i] = 0x80;
            }

            //put the length
            nt_buffer[14] = (uint)length << 4;

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // NTLM hash calculation
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            uint a = INIT_A;
            uint b = INIT_B;
            uint c = INIT_C;
            uint d = INIT_D;

            /* Round 1 */
            a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);

            /* Round 2 */
            a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

            /* Round 3 */
            a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);

            output[0] = a + INIT_A;
            output[1] = b + INIT_B;
            output[2] = c + INIT_C;
            output[3] = d + INIT_D;

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // Convert the hash to hex (for being readable)
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            for (i = 0; i < 4; i++)
            {
                int j = 0;
                uint n = output[i];
                //iterate the bytes of the integer
                for (; j < 4; j++)
                {
                    uint convert = n % 256;
                    hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
                    convert = convert / 16;
                    hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
                    n = n / 256;
                }
            }

            return string.Join(string.Empty, hex_format);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            maHoaMD5();
            textBox3.Text = maHoaSHA1(textBox1.Text);
            textBox4.Text = maHoaSHA256(textBox1.Text);
            textBox5.Text = Ntlm(textBox1.Text);

        }
    }
}
