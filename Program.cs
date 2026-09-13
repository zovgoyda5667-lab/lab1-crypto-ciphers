using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Lab1Crypto
{
    class Program
    {
        static readonly HashSet<string> Dictionary = new HashSet<string>(
            @"the a is of and to in that it as with for be this you your i are on
              at by not have has we they he she was were will would can cipher key
              letter substitution result same different encrypted length plaintext
              algorithm text example number shift help good luck test"
            .Split((char[])null, StringSplitOptions.RemoveEmptyEntries));

        const string Ciphertext1 =
            "afgiq, g dqwqwrqd lpal sec patq an gwvedlanl idsvleydavps lqul iewgny cv. " +
            "g aw upadgny ws gntafcarfq onekfqzyq eh lpq iaquad igvpqd kglp sec. lpq " +
            "iaquad igvpqd gu a ifauugi weneafvparqlgi ucrulglclgen igvpqd. qaip fqllqd gn " +
            "lpq vfagnlqbl gu dqvfaiqz rs a fqllqd a hgbqz ncwrqd eh veuglgenu hcdlpqd afeny " +
            "gn lpq afvparql; lpgu ncwrqd gu iaffqz lpq oqs, ed upghl. hed qbawvfq, kglp a " +
            "upghl eh 3, lpq fqllqd a rqiewqu z, anz j rqiewqu i. zqidsvlgen gu vqdhedwqz rs " +
            "upghlgny lpq fqllqdu gn lpq evveuglq zgdqilgen. g pevq lpgu kgff pqfv sec vauu " +
            "lpq lqul. g kgup sec yeez fcio!";

        const string Ciphertext2 =
            "jyb pzang ywm fwf ywmr lslf. k wwmlb rims tw jount wmt pzap eoyf cujhkf " +
            "ig sage tw wrawk. u heskdkh tw qwubcl bo a coxs swjhuqtuwapsd sragqisal " +
            "skplsr and szogs tls vuoen`efe skplsr. lsrk ks gymk lrusf unfwfmabiwn ajyup kt. " +
            "pze hkgknexs cujhkf ig a cvasgkc fylialfzajstuw sylspktybiwn cujhkf. ip mskq " +
            "a msyqyrb ihwqe vstpsrg hepsreknk hitdexsnp qhudtg, qieklaf tw bhwqe yqeb " +
            "kn pze saegar skplsr. pze msyqyrb ks xspkatkh unbiv kt eatszeg bhk renotl yf " +
            "pze frauntktt. kacl repbex yf pze frauntktt uq tlsn kncxeppsd yqino tls slkfp " +
            "hepsreknkh bi bhk woxfegjonhino lkbtkf ot bhk geiioxh. ag a rkquvb, tls sace " +
            "frauntktt vstpsr eay js enwrijtkh ag hitdexsnp wifzexbezb lkbtkfs.";

        const string Ciphertext3 =
            "YKDTMOCHDGYRQDKBPGMEVGLWOMNTQVSACYFPBSRYPTPKBLEKYFQHLXO" +
            "DEMOEBLDHMAGVLZENPKCZPKBL";

        const string PlayfairSquare = "CRYPTOABDEFGHIKLMNQSUVWXZ";

        static int Mod(int a, int m) => ((a % m) + m) % m;

        static int ModInverse(int a, int m)
        {
            int g = m, x0 = 0, x1 = 1, aa = a;
            while (aa != 0)
            {
                int q = g / aa;
                (g, aa) = (aa, g - q * aa);
                (x0, x1) = (x1, x0 - q * x1);
            }
            return Mod(x0, m);
        }

        static int Gcd(int a, int b) => b == 0 ? a : Gcd(b, a % b);

        static string MultCaesarDecrypt(string text, int kInv)
        {
            var sb = new StringBuilder();
            foreach (char ch in text)
            {
                if (char.IsLetter(ch))
                {
                    char baseCh = char.IsLower(ch) ? 'a' : 'A';
                    int val = ch - baseCh;
                    sb.Append((char)(Mod(val * kInv, 26) + baseCh));
                }
                else sb.Append(ch);
            }
            return sb.ToString();
        }

        static int ScoreText(string text)
        {
            var words = Regex.Matches(text.ToLower(), "[a-z]+").Select(m => m.Value);
            return words.Count(w => Dictionary.Contains(w));
        }

        static (int k, int kInv, string plain) BreakMultCaesar(string ciphertext)
        {
            int bestK = 0, bestKInv = 0, bestScore = -1;
            string bestPlain = "";
            for (int k = 1; k < 26; k++)
            {
                if (Gcd(k, 26) != 1) continue;
                int kInv = ModInverse(k, 26);
                string decrypted = MultCaesarDecrypt(ciphertext, kInv);
                int score = ScoreText(decrypted);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestK = k;
                    bestKInv = kInv;
                    bestPlain = decrypted;
                }
            }
            return (bestK, bestKInv, bestPlain);
        }

        static string MultVigenereDecrypt(string text, int[] kInvs)
        {
            var sb = new StringBuilder();
            int idx = 0;
            int n = kInvs.Length;
            foreach (char ch in text)
            {
                if (char.IsLetter(ch))
                {
                    char baseCh = char.IsLower(ch) ? 'a' : 'A';
                    int val = ch - baseCh;
                    int kInv = kInvs[idx % n];
                    sb.Append((char)(Mod(val * kInv, 26) + baseCh));
                    idx++;
                }
                else sb.Append(ch);
            }
            return sb.ToString();
        }

        static (int[] key, int[] kInvs, string plain) BreakMultVigenere(string ciphertext, int keyLen = 3)
        {
            var validKeys = Enumerable.Range(1, 25).Where(k => Gcd(k, 26) == 1).ToArray();
            int bestScore = -1;
            int[]? bestKey = null;
            int[]? bestKInvs = null;
            string bestPlain = "";

            void Recurse(int[] combo, int pos)
            {
                if (pos == keyLen)
                {
                    var kInvs = combo.Select(k => ModInverse(k, 26)).ToArray();
                    string decrypted = MultVigenereDecrypt(ciphertext, kInvs);
                    int score = ScoreText(decrypted);
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestKey = (int[])combo.Clone();
                        bestKInvs = kInvs;
                        bestPlain = decrypted;
                    }
                    return;
                }
                foreach (var k in validKeys)
                {
                    combo[pos] = k;
                    Recurse(combo, pos + 1);
                }
            }

            Recurse(new int[keyLen], 0);
            return (bestKey!, bestKInvs!, bestPlain);
        }

        static (char[,] grid, Dictionary<char, (int r, int c)> pos) BuildGrid(string square)
        {
            var grid = new char[5, 5];
            var pos = new Dictionary<char, (int r, int c)>();
            for (int i = 0; i < 25; i++)
            {
                int r = i / 5, c = i % 5;
                grid[r, c] = square[i];
                pos[square[i]] = (r, c);
            }
            return (grid, pos);
        }

        static string PlayfairDecrypt(string ciphertext, string square = PlayfairSquare)
        {
            var (grid, pos) = BuildGrid(square);
            var sb = new StringBuilder();
            for (int i = 0; i < ciphertext.Length; i += 2)
            {
                char a = ciphertext[i], b = ciphertext[i + 1];
                var (ra, ca) = pos[a];
                var (rb, cb) = pos[b];
                if (ra == rb)
                {
                    sb.Append(grid[ra, Mod(ca - 1, 5)]);
                    sb.Append(grid[rb, Mod(cb - 1, 5)]);
                }
                else if (ca == cb)
                {
                    sb.Append(grid[Mod(ra - 1, 5), ca]);
                    sb.Append(grid[Mod(rb - 1, 5), cb]);
                }
                else
                {
                    sb.Append(grid[ra, cb]);
                    sb.Append(grid[rb, ca]);
                }
            }
            return sb.ToString();
        }

        static void Main()
        {
            Console.WriteLine(new string('=', 70));
            Console.WriteLine("Задание 1. Взлом модифицированного шифра Цезаря (Боб)");
            Console.WriteLine(new string('=', 70));
            var (k1, k1Inv, plain1) = BreakMultCaesar(Ciphertext1);
            Console.WriteLine($"Найденный ключ шифрования k = {k1} (обратный элемент k^-1 mod 26 = {k1Inv})");
            Console.WriteLine("Расшифрованное сообщение:\n");
            Console.WriteLine(plain1);

            Console.WriteLine();
            Console.WriteLine(new string('=', 70));
            Console.WriteLine("Задание 2. Взлом модифицированного шифра Виженера (Алиса)");
            Console.WriteLine(new string('=', 70));
            var (key2, kInvs2, plain2) = BreakMultVigenere(Ciphertext2, 3);
            Console.WriteLine($"Найденный ключ шифрования (k1,k2,k3) = ({string.Join(", ", key2)})");
            Console.WriteLine($"Обратные элементы mod 26 = [{string.Join(", ", kInvs2)}]");
            Console.WriteLine("Расшифрованное сообщение:\n");
            Console.WriteLine(plain2);

            Console.WriteLine();
            Console.WriteLine(new string('=', 70));
            Console.WriteLine("Задание 3. Шифр 1854 года (Плейфер) — расшифровка криптограммы");
            Console.WriteLine(new string('=', 70));
            Console.WriteLine("Ключевая таблица (5x5) построена по слову CRYPTO:");
            var (grid, _) = BuildGrid(PlayfairSquare);
            for (int r = 0; r < 5; r++)
            {
                var row = Enumerable.Range(0, 5).Select(c => grid[r, c].ToString());
                Console.WriteLine(string.Join(" ", row));
            }
            string plain3 = PlayfairDecrypt(Ciphertext3);
            Console.WriteLine("\nРасшифрованный текст:\n");
            Console.WriteLine(plain3);
        }
    }
}
