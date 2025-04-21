package main

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"golang.org/x/exp/slices"
	"os"
	"strconv"
	"strings"
)

// Data represents a row in the CSV file
type Data struct {
	ECDataCsEcrecover string
	ECDataID          string
	ECDataIndex       string
	ECDataLimb        string
	ECDataSuccessBit  string
	ECDataIsData      string
	ECDataIsRes       string
}

func toByteArray(value uint64, length int) []byte {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte(value & 0xFF)
		value >>= 8
	}

	for len(result) > 0 && result[len(result)-1] == 0 {
		result = result[:len(result)-1]
	}
	return result
}

func divideTo30BitLimbs(data []byte) [][]byte {
	var limbs [][]byte
	bitBuffer := uint64(0)
	bitCount := 0

	for _, b := range data {
		bitBuffer |= uint64(b) << bitCount
		bitCount += 8

		for bitCount >= 30 {
			limb := toByteArray(bitBuffer&0x3FFFFFFF, 4)
			slices.Reverse(limb)
			limbs = append(limbs, limb)
			bitBuffer >>= 30
			bitCount -= 30
		}
	}

	if bitCount > 0 {
		limb := toByteArray(bitBuffer, 4)
		slices.Reverse(limb)
		limbs = append(limbs, limb)
	}

	return limbs
}

func mergeLimbs(limb1, limb2 string) string {
	if limb1 == "0" {
		return limb2
	}

	return limb1 + limb2
}

func writeCsv(name string, dataEntries []Data) {
	// Open a new CSV file for writing
	file, err := os.Create(name)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Create a CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	var limbNames []string
	for i := 0; i < 9; i++ {
		limbNames = append(limbNames, fmt.Sprintf("EC_DATA_LIMB_%d", i))
	}

	// Write the header row
	header := []string{
		"EC_DATA_CS_ECRECOVER", "EC_DATA_ID", "EC_DATA_LIMB", "EC_DATA_SUCCESS_BIT", "EC_DATA_INDEX", "EC_DATA_IS_DATA", "EC_DATA_IS_RES",
	}

	if err := writer.Write(header); err != nil {
		fmt.Println("Error writing header:", err)
		return
	}

	// Write each data entry to the CSV file
	for _, entry := range dataEntries {
		row := []string{
			entry.ECDataCsEcrecover,
			entry.ECDataID,
			entry.ECDataLimb,
			entry.ECDataSuccessBit,
			entry.ECDataIndex,
			entry.ECDataIsData,
			entry.ECDataIsRes,
		}

		if err := writer.Write(row); err != nil {
			fmt.Println("Error writing row:", err)
			return
		}
	}
}

func main() {
	// Open the CSV file
	file, err := os.Open("ecdata_test.csv")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Create a new CSV reader
	reader := csv.NewReader(file)

	// Read all rows from the CSV file
	rows, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	// Ensure the file has a header row
	if len(rows) < 2 {
		fmt.Println("CSV file is empty or missing header row.")
		return
	}

	// Parse the rows into the Data structure
	var dataEntries []Data
	for i, row := range rows[1:] {
		if len(row) != 7 {
			fmt.Printf("Skipping row %d due to incorrect number of columns\n", i+1)
			continue
		}

		dataEntry := Data{
			ECDataCsEcrecover: row[0],
			ECDataID:          row[1],
			ECDataLimb:        row[2][2:],
			ECDataSuccessBit:  row[3],
			ECDataIndex:       row[4],
			ECDataIsData:      row[5],
			ECDataIsRes:       row[6],
		}

		dataEntries = append(dataEntries, dataEntry)
	}

	if len(dataEntries)%2 != 0 {
		panic("Number of data entries should even")
	}

	instanceNum := len(dataEntries) / 2

	var mergedEntries []Data
	index := 0

	for i := 0; i < len(dataEntries); i += 2 {
		limb := mergeLimbs(dataEntries[i].ECDataLimb, dataEntries[i+1].ECDataLimb)

		if len(limb) < 64 {
			limb += strings.Repeat("0", 64-len(limb))
		}

		limbBytes, _ := hex.DecodeString(limb)
		limbs := divideTo30BitLimbs(limbBytes)

		if dataEntries[i].ECDataIsRes == "1" || i%10 == 0 {
			index = 0
		}

		slices.Reverse(limbs)
		for _, limbb := range limbs {
			if len(limbb) == 0 {
				limbb = []byte{0}
			}

			mergedEntries = append(mergedEntries, Data{
				ECDataCsEcrecover: dataEntries[i].ECDataCsEcrecover,
				ECDataID:          strconv.Itoa(i / instanceNum),
				ECDataIndex:       strconv.Itoa(index),
				ECDataLimb:        "0x" + hex.EncodeToString(limbb),
				ECDataSuccessBit:  dataEntries[i].ECDataSuccessBit,
				ECDataIsData:      dataEntries[i].ECDataIsData,
				ECDataIsRes:       dataEntries[i].ECDataIsRes,
			})

			index += 1
		}
	}

	writeCsv("ecdata_out_new.csv", mergedEntries)
	//combineFrom128BitNumbers

}
