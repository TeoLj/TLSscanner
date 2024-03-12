package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"
	"strconv"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	
	
)

type Analyzer struct {
	ScannedCiphers []string
	CSVFilePath   string
	ScanAndSaveDirectory string
	cipherCount    map[string]int
	Mutex		  *sync.Mutex // fine grained locking
}


func NewAnalyzer(scanner Scanner) *Analyzer {
	return &Analyzer{
		ScannedCiphers: scanner.ScannedCiphers,
		ScanAndSaveDirectory: scanner.opts.ScanAndSaveDirectory,
		CSVFilePath:   scanner.opts.CSVFilePath,
		cipherCount:    make(map[string]int),
		Mutex:          &sync.Mutex{},
	}
}

func (a *Analyzer) Run(){

	a.CountCiphers()
	fileName := strings.TrimSuffix(strings.TrimPrefix(a.CSVFilePath, "./"), ".csv")

	if a.ScanAndSaveDirectory != "" {
		os.Chdir(a.ScanAndSaveDirectory)
		
		a.SaveCiphersCount(a.ScanAndSaveDirectory +  "/" + fileName +"_cipherCounts.csv")
		a.PlotCipherCountsFromCSV(a.ScanAndSaveDirectory+  "/" + fileName +"_cipherCounts.csv", a.ScanAndSaveDirectory + "/" + fileName +"/_plot.html")
	} else {
		
		a.SaveCiphersCount("./output/"+ fileName+"_cipherCounts.csv")
		a.PlotCipherCountsFromCSV("./output/"+ fileName+"_cipherCounts.csv", "./output/"+fileName+"_plot.html")
		
	}
	
}

func (a *Analyzer) CountCiphers() map[string]int {

	// Iterate over the scanned ciphers, assuming each entry is a domain followed by a list of ciphers
	for _, scanned := range a.ScannedCiphers {
		// Assuming each entry in ScannedCiphers is a string like "domain: cipher1,cipher2,cipher3" (specified in ScanDomain)
		// Split the string into domain and ciphers part
		parts := strings.Split(scanned, ": ")
		if len(parts) != 2 {
			fmt.Println("Unexpected format in ScannedCiphers, skipping:", scanned)
			continue
		}
		// Now parts[1] contains "cipher1;cipher2;cipher3", split these into individual ciphers
		ciphers := strings.Split(parts[1], ";")

		// Count each cipher occurrence
		for _, cipher := range ciphers {
			if cipher != "" {
				a.cipherCount[cipher]++
			}
		}
	}
	// Now print the count of each cipher suite
	fmt.Println("\n\033[1;33mCipher suite occurrences:\033[0m")
	for cipher, count := range a.cipherCount {
		fmt.Printf("%s: \033[1;34m%d\033[0m\n", cipher, count)
	}
	return a.cipherCount
}

func (a *Analyzer) SaveCiphersCount(filename string) {

	a.Mutex.Lock()
	defer a.Mutex.Unlock()

	// open the file for writing
	file, err := os.Create(filename)
	file.Truncate(0) // Overwrite the old content of output.csv

	if err != nil {
		fmt.Println("Error creating CSV file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write the header
	writer.Write([]string{"Cipher", "Count"})
	for cipher, count := range a.cipherCount {
		writer.Write([]string{cipher, fmt.Sprintf("%d", count)})
	}
}


func (a *Analyzer) PlotCipherCountsFromCSV(filenameIn string, filenameOut string) {
	// Open the CSV file
	file, err := os.Open(filenameIn)

	if err != nil {
		fmt.Println("Error opening CSV file:", err)
		return
	}
	defer file.Close()

	// Read the CSV records
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV file:", err)
		return
	}

	// Extract the keys and values from the CSV records
	keys := make([]string, 0, len(records)-1)
	values := make([]opts.BarData, 0, len(records)-1)
	for i, record := range records {
		if i == 0 { // Skip the header
			continue
		}
		keys = append(keys, record[0])
		value, err := strconv.Atoi(record[1])
		if err != nil {
			fmt.Println("Error converting value to int:", err)
			return
		}
		values = append(values, opts.BarData{Value: value})
	}

	// Create a new bar instance
	bar := charts.NewBar()

	bar.SetGlobalOptions(
		// Set the chart title
		charts.WithTitleOpts(opts.Title{
			Title: "Cipher Suite Occurrences",
		}),
		// Set the toolbox options
		charts.WithToolboxOpts(opts.Toolbox{
			Show: true,
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{
					Show:  true,
					Title: "Save as Image",
					Name:  "Cipher Suite Occurrences",
					Type:  "png",
				},
				DataView: &opts.ToolBoxFeatureDataView{
					Show:  true,
					Title: "Data View",
					Lang:  []string{"Data View", "Close", "Refresh"},
				},
			},
		}),
		// Set the chart initialization options
		charts.WithInitializationOpts(opts.Initialization{
			PageTitle: "Cipher Suite Occurrences",
			Width:     "1100px",
			Height:    "700px",
		}),
	)

	bar.SetGlobalOptions(
		// Set the X-axis options
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{
				Show:        true,
				Interval:    "auto",
				Rotate:      60,
				Formatter:   "{value}",
				ShowMaxLabel: true,
				ShowMinLabel: true,
			},
		}),
		// Adjust the grid options to increase the bottom margin
		charts.WithGridOpts(opts.Grid{
			Bottom: "50%", // Adjust this value as needed to provide enough space
		}),
		// Add a tooltip to the bar (cursor hover over bar to see value)
		charts.WithTooltipOpts(opts.Tooltip{
			Show:        true,
			Trigger:     "axis",
			AxisPointer: &opts.AxisPointer{Type: "shadow"},
		}),
	)

	// Add the data to the bar
	bar.SetXAxis(keys).
		AddSeries("Occurrences", values).
		SetSeriesOptions(
			// Set the bar chart options
			charts.WithBarChartOpts(opts.BarChart{
				BarGap:         "0%",    // No gap between bars of different categories
				BarCategoryGap: "40%",   // Gap between bars of the same category (thinner)
			}),
		)

	bar.SetXAxis(keys).
		SetSeriesOptions(charts.WithMarkLineNameTypeItemOpts(
			opts.MarkLineNameTypeItem{Name: "Maximum", Type: "max"},
			opts.MarkLineNameTypeItem{Name: "Minimum", Type: "min"},
		))

	// Save to file
	f, _ := os.Create(filenameOut)
	bar.Render(f)
}

