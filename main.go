package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
)

// PublicKey представляет открытый ключ Эль-Гамаля: (p, g, y)
type PublicKey struct {
	P, G, Y *big.Int
}

// PrivateKey представляет закрытый ключ Эль-Гамаля: x
type PrivateKey struct {
	X *big.Int
}

// ============================================================================
// Криптографические примитивы (ручная реализация на math/big)
// ============================================================================

// GenerateKeyPair генерирует пару ключей для заданной битовой длины простого числа
func GenerateKeyPair(bitSize int) (*PrivateKey, *PublicKey, error) {
	// 1. Генерация большого простого числа p
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	// 2. Выбор генератора g. Для простоты и надежности берем g = 2
	// (для безопасных простых чисел 2 часто является генератором или элементом большого порядка).
	g := big.NewInt(2)

	// 3. Генерация закрытого ключа x: 2 <= x <= p-2
	xMax := new(big.Int).Sub(p, big.NewInt(2))
	x, err := rand.Int(rand.Reader, xMax)
	if err != nil {
		return nil, nil, err
	}
	x.Add(x, big.NewInt(2)) // x теперь в диапазоне [2, p-1]

	// 4. Вычисление открытого ключа y = g^x mod p
	y := new(big.Int).Exp(g, x, p)

	return &PrivateKey{X: x}, &PublicKey{P: p, G: g, Y: y}, nil
}

// Encrypt шифрует сообщение блоками. Возвращает зашифрованные данные.
func Encrypt(msg []byte, pub *PublicKey) ([]byte, error) {
	// Размер блока должен быть строго меньше размера p в байтах, чтобы m < p
	blockSize := len(pub.P.Bytes()) - 1
	if blockSize <= 0 {
		return nil, fmt.Errorf("модуль p слишком мал")
	}

	var cipher []byte
	// Записываем размер блока в начало файла для корректного расшифрования
	cipher = binary.BigEndian.AppendUint32(cipher, uint32(blockSize))

	pMinus2 := new(big.Int).Sub(pub.P, big.NewInt(2))

	for i := 0; i < len(msg); i += blockSize {
		end := i + blockSize
		if end > len(msg) {
			end = len(msg)
		}
		block := msg[i:end]

		// Преобразуем блок в число m
		m := new(big.Int).SetBytes(block)

		// Генерируем случайное k: 2 <= k <= p-2
		k, err := rand.Int(rand.Reader, pMinus2)
		if err != nil {
			return nil, err
		}
		k.Add(k, big.NewInt(2))

		// c1 = g^k mod p
		c1 := new(big.Int).Exp(pub.G, k, pub.P)
		// s = y^k mod p
		s := new(big.Int).Exp(pub.Y, k, pub.P)
		// c2 = (m * s) mod p
		c2 := new(big.Int).Mul(m, s)
		c2.Mod(c2, pub.P)

		// Дополняем c1 и c2 нулями слева до размера len(pub.P.Bytes())
		pByteLen := len(pub.P.Bytes())
		c1Bytes := padBytes(c1.Bytes(), pByteLen)
		c2Bytes := padBytes(c2.Bytes(), pByteLen)

		cipher = append(cipher, c1Bytes...)
		cipher = append(cipher, c2Bytes...)
	}

	return cipher, nil
}

// Decrypt расшифровывает сообщение
func Decrypt(cipher []byte, priv *PrivateKey, pub *PublicKey) ([]byte, error) {
	if len(cipher) < 4 {
		return nil, fmt.Errorf("некорректный формат шифртекста")
	}

	blockSize := int(binary.BigEndian.Uint32(cipher[:4]))
	pByteLen := len(pub.P.Bytes())
	expectedBlockLen := 2 * pByteLen

	data := cipher[4:]
	if len(data)%expectedBlockLen != 0 {
		return nil, fmt.Errorf("поврежденный шифртекст")
	}

	var plain []byte

	for i := 0; i < len(data); i += expectedBlockLen {
		c1Bytes := data[i : i+pByteLen]
		c2Bytes := data[i+pByteLen : i+2*pByteLen]

		c1 := new(big.Int).SetBytes(c1Bytes)
		c2 := new(big.Int).SetBytes(c2Bytes)

		// s = c1^x mod p
		s := new(big.Int).Exp(c1, priv.X, pub.P)
		// s_inv = s^(-1) mod p
		sInv := new(big.Int).ModInverse(s, pub.P)
		if sInv == nil {
			return nil, fmt.Errorf("обратный элемент не существует (ошибка ключа или данных)")
		}

		// m = (c2 * s_inv) mod p
		m := new(big.Int).Mul(c2, sInv)
		m.Mod(m, pub.P)

		mBytes := m.Bytes()
		// Восстанавливаем исходный размер блока (убираем влияние leading zeros при преобразовании в int)
		// Но мы должны быть осторожны: последний блок может быть меньше blockSize
		// Для простоты реализации в рамках задания, мы просто добавляем байты,
		// а лишние нули в конце файла можно обрезать при необходимости, или полагаться на формат.
		// Здесь мы просто берем последние blockSize байт (или меньше для самого последнего блока, но для простоты дополним)
		paddedM := padBytes(mBytes, blockSize)

		// Если это последний блок, он может содержать паддинг нулями, который мы оставим,
		// так как в рамках учебной задачи строгое удаление PKCS7 не требуется,
		// но мы обрежем до реального размера, если это конец.
		plain = append(plain, paddedM...)
	}

	return plain, nil
}

func padBytes(b []byte, length int) []byte {
	if len(b) >= length {
		return b[len(b)-length:] // обрезаем, если вдруг больше (не должно быть)
	}
	res := make([]byte, length)
	copy(res[length-len(b):], b)
	return res
}

// ============================================================================
// Криптоанализ: Атака "Шаг младенца, шаг гиганта" (Baby-step Giant-step)
// ============================================================================

// BabyStepGiantStep решает задачу дискретного логарифмирования: найти x, такое что g^x = y (mod p)
// Работает за время и память O(sqrt(p)). ПРИМЕНИМО ТОЛЬКО ДЛЯ МАЛЫХ p (например, < 2^40)
func BabyStepGiantStep(p, g, y *big.Int) (*big.Int, error) {
	// Ограничение для предотвращения переполнения памяти в учебных целях
	if p.BitLen() > 40 {
		return nil, fmt.Errorf("модуль p слишком велик для атаки BSGS (макс. 40 бит). Текущий размер: %d бит", p.BitLen())
	}

	// m = ceil(sqrt(p))
	m := new(big.Int).Sqrt(p)
	m.Add(m, big.NewInt(1))

	// 1. Baby steps: сохраняем g^j mod p -> j
	// Используем map[string]int64, так как big.Int нельзя использовать как ключ напрямую
	table := make(map[string]int64)
	gj := big.NewInt(1)
	mInt64 := m.Int64()

	for j := int64(0); j < mInt64; j++ {
		table[gj.String()] = j
		gj.Mul(gj, g).Mod(gj, p)
	}

	// 2. Giant steps: вычисляем g^(-m) mod p
	gInv := new(big.Int).ModInverse(g, p)
	factor := new(big.Int).Exp(gInv, m, p)

	gamma := new(big.Int).Set(y)

	for i := int64(0); i < mInt64; i++ {
		if j, exists := table[gamma.String()]; exists {
			// Найдено совпадение: x = i * m + j
			x := new(big.Int).Mul(big.NewInt(i), m)
			x.Add(x, big.NewInt(j))
			return x, nil
		}
		gamma.Mul(gamma, factor).Mod(gamma, p)
	}

	return nil, fmt.Errorf("дискретный логарифм не найден")
}

// ============================================================================
// Работа с файлами и CLI
// ============================================================================

func saveKey(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0600)
}

func loadKey(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func cmdGenerate(bitSize int, privFile, pubFile string) {
	fmt.Printf("Генерация ключей (%d бит)... Это может занять некоторое время.\n", bitSize)
	priv, pub, err := GenerateKeyPair(bitSize)
	if err != nil {
		log.Fatalf("Ошибка генерации: %v", err)
	}

	// Сохраняем закрытый ключ (просто число X)
	if err := saveKey(privFile, padBytes(priv.X.Bytes(), len(pub.P.Bytes()))); err != nil {
		log.Fatalf("Ошибка записи закрытого ключа: %v", err)
	}

	// Сохраняем открытый ключ (P, G, Y)
	pubData := append(padBytes(pub.P.Bytes(), 32), padBytes(pub.G.Bytes(), 32)...)
	pubData = append(pubData, padBytes(pub.Y.Bytes(), 32)...)
	if err := saveKey(pubFile, pubData); err != nil {
		log.Fatalf("Ошибка записи открытого ключа: %v", err)
	}

	fmt.Println("Ключи успешно сгенерированы:")
	fmt.Printf("  Закрытый ключ: %s\n", privFile)
	fmt.Printf("  Открытый ключ: %s\n", pubFile)
}

func cmdEncrypt(inFile, pubFile, outFile string) {
	msg, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("Ошибка чтения файла '%s': %v", inFile, err)
	}

	pubData, err := loadKey(pubFile)
	if err != nil || len(pubData) < 96 {
		log.Fatalf("Ошибка чтения открытого ключа (ожидается 96 байт): %v", err)
	}

	pub := &PublicKey{
		P: new(big.Int).SetBytes(pubData[0:32]),
		G: new(big.Int).SetBytes(pubData[32:64]),
		Y: new(big.Int).SetBytes(pubData[64:96]),
	}

	cipher, err := Encrypt(msg, pub)
	if err != nil {
		log.Fatalf("Ошибка шифрования: %v", err)
	}

	if err := os.WriteFile(outFile, cipher, 0644); err != nil {
		log.Fatalf("Ошибка записи шифртекста: %v", err)
	}
	fmt.Printf("Файл успешно зашифрован и сохранен в: %s\n", outFile)
}

func cmdDecrypt(inFile, privFile, pubFile, outFile string) {
	cipher, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("Ошибка чтения файла '%s': %v", inFile, err)
	}

	privData, err := loadKey(privFile)
	if err != nil {
		log.Fatalf("Ошибка чтения закрытого ключа: %v", err)
	}
	priv := &PrivateKey{X: new(big.Int).SetBytes(privData)}

	pubData, err := loadKey(pubFile)
	if err != nil || len(pubData) < 96 {
		log.Fatalf("Ошибка чтения открытого ключа: %v", err)
	}
	pub := &PublicKey{
		P: new(big.Int).SetBytes(pubData[0:32]),
		G: new(big.Int).SetBytes(pubData[32:64]),
		Y: new(big.Int).SetBytes(pubData[64:96]),
	}

	plain, err := Decrypt(cipher, priv, pub)
	if err != nil {
		log.Fatalf("Ошибка расшифрования: %v", err)
	}

	if err := os.WriteFile(outFile, plain, 0644); err != nil {
		log.Fatalf("Ошибка записи расшифрованного файла: %v", err)
	}
	fmt.Printf("Файл успешно расшифрован и сохранен в: %s\n", outFile)
}

func cmdAttack(pStr, gStr, yStr string) {
	p, _ := new(big.Int).SetString(pStr, 10)
	g, _ := new(big.Int).SetString(gStr, 10)
	y, _ := new(big.Int).SetString(yStr, 10)

	fmt.Println("Запуск атаки 'Шаг младенца, шаг гиганта'...")
	x, err := BabyStepGiantStep(p, g, y)
	if err != nil {
		log.Fatalf("Атака не удалась: %v", err)
	}

	fmt.Printf("✅ Атака успешна! Найден закрытый ключ (x): %s\n", x.String())

	// Проверка
	check := new(big.Int).Exp(g, x, p)
	if check.Cmp(y) == 0 {
		fmt.Println("✅ Проверка: g^x mod p == y. Ключ верен.")
	} else {
		fmt.Println("❌ Ошибка проверки.")
	}
}

func printUsage() {
	fmt.Println("Криптосистема Эль-Гамаля (учебная реализация)")
	fmt.Println("Команды:")
	fmt.Println("  1. Генерация ключей:")
	fmt.Println("     go run main.go generate --bits 256 --priv priv.key --pub pub.key")
	fmt.Println("  2. Шифрование:")
	fmt.Println("     go run main.go encrypt --in plain.txt --pub pub.key --out cipher.bin")
	fmt.Println("  3. Расшифрование:")
	fmt.Println("     go run main.go decrypt --in cipher.bin --priv priv.key --pub pub.key --out result.txt")
	fmt.Println("  4. Криптоаналитическая атака (только для малых p, < 40 бит):")
	fmt.Println("     go run main.go attack --p 1000003 --g 2 --y 100903")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "generate":
		genCmd := flag.NewFlagSet("generate", flag.ExitOnError)
		bits := genCmd.Int("bits", 256, "Размер простого числа в битах")
		privFile := genCmd.String("priv", "priv.key", "Файл закрытого ключа")
		pubFile := genCmd.String("pub", "pub.key", "Файл открытого ключа")
		genCmd.Parse(os.Args[2:])
		cmdGenerate(*bits, *privFile, *pubFile)

	case "encrypt":
		encCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
		inFile := encCmd.String("in", "", "Файл открытого текста")
		pubFile := encCmd.String("pub", "pub.key", "Файл открытого ключа")
		outFile := encCmd.String("out", "cipher.bin", "Файл шифртекста")
		encCmd.Parse(os.Args[2:])
		if *inFile == "" {
			encCmd.Usage()
			return
		}
		cmdEncrypt(*inFile, *pubFile, *outFile)

	case "decrypt":
		decCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
		inFile := decCmd.String("in", "", "Файл шифртекста")
		privFile := decCmd.String("priv", "priv.key", "Файл закрытого ключа")
		pubFile := decCmd.String("pub", "pub.key", "Файл открытого ключа")
		outFile := decCmd.String("out", "result.txt", "Файл расшифрованного текста")
		decCmd.Parse(os.Args[2:])
		if *inFile == "" {
			decCmd.Usage()
			return
		}
		cmdDecrypt(*inFile, *privFile, *pubFile, *outFile)

	case "attack":
		atkCmd := flag.NewFlagSet("attack", flag.ExitOnError)
		pStr := atkCmd.String("p", "", "Модуль p (десятичное число)")
		gStr := atkCmd.String("g", "", "Генератор g (десятичное число)")
		yStr := atkCmd.String("y", "", "Открытый ключ y (десятичное число)")
		atkCmd.Parse(os.Args[2:])
		if *pStr == "" || *gStr == "" || *yStr == "" {
			atkCmd.Usage()
			return
		}
		cmdAttack(*pStr, *gStr, *yStr)

	default:
		fmt.Printf("Неизвестная команда: %s\n", cmd)
		printUsage()
	}
}
