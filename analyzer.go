package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	//"github.com/go-echarts/go-echarts/v2/types"
	
)




type Analyzer struct {
	ScannedCiphers []string
	SaveResults bool
	SaveResultsDirectory string
	cipherCount    map[string]int
	Mutex		  *sync.Mutex // fine grained locking
}

// uses Struct elements Domains[]string, ScannedCiphers []string to analyze occurence of ciphers

func NewAnalyzer(scanner Scanner) *Analyzer {
	return &Analyzer{
		ScannedCiphers: scanner.ScannedCiphers,
		SaveResults: scanner.opts.SaveResults,
		SaveResultsDirectory: scanner.opts.SaveResultsDirectory,
		cipherCount:    make(map[string]int),
		Mutex:          &sync.Mutex{},
	}
}

func (a *Analyzer) Run(){

	a.AnalyzeCiphers()

	if a.SaveResults {
		if a.SaveResultsDirectory != "" {
			os.Chdir(a.SaveResultsDirectory)
			a.SaveCiphersCount(a.SaveResultsDirectory + "/cipherCounts.csv")
			//a.PlotResults(a.SaveResultsDirectory + "/cipherCounts_plot.png", a.cipherCount)
		} else {
			// Create a folder called output to save the results if it doesn't exist
			if _, err := os.Stat("output"); os.IsNotExist(err) {
				os.Mkdir("output", 0755)
			}
			a.SaveCiphersCount("./output/cipherCounts.csv")
			a.PlotResults(a.cipherCount)
			//a.PlotResults("./output/cipherCounts_plot.png", a.cipherCount)
		}
	}
}

func (a *Analyzer) AnalyzeCiphers() map[string]int {

	// Iterate over the scanned ciphers, assuming each entry is a domain followed by a list of ciphers
	for _, scanned := range a.ScannedCiphers {
		// Assuming each entry in ScannedCiphers is a string like "domain: cipher1;cipher2;cipher3" (specified in ScanDomain)
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
			a.cipherCount[cipher]++
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


func (a *Analyzer) PlotResults(items map[string]int) {

	// Create a new bar instance
    bar := charts.NewBar()


	bar.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "Cipher Suite Occurrences",
		}),
		
		charts.WithToolboxOpts(opts.Toolbox{
			Show: true,
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{
					Show: true,
					Title: "Save as Image",
					Name: "Cipher Suite Occurrences",
					
				},

				DataView: &opts.ToolBoxFeatureDataView{
					Show: true,
					Title: "Data View",
					Lang: []string{"Data View", "Close", "Refresh"},


				},
			},
		}),

		charts.WithInitializationOpts(opts.Initialization{
			PageTitle: "Cipher Suite Occurrences",
			Width: "1100px",
			Height: "700px",
		}),

		

		
	)
    bar.SetGlobalOptions(charts.WithXAxisOpts(opts.XAxis{
		AxisLabel: &opts.AxisLabel{
			Show: true,
			Interval: "auto",
			Rotate: 34,
			Formatter: "{value}",
			ShowMaxLabel: true,
			ShowMinLabel: true,

		},
	}),
	
	 // Adjust the grid options to increase the bottom margin
	charts.WithGridOpts(opts.Grid{
        Bottom: "50%", // Adjust this value as needed to provide enough space
	
   }),

)


	// Add data to bar
	keys := make([]string, 0, len(items))
	values := make([]opts.BarData, 0, len(items)) // Convert values to []opts.BarData
	for k, v := range items {
		keys = append(keys, k)
		values = append(values, opts.BarData{Value: v}) // Wrap each value in opts.BarData
	}
	bar.SetXAxis(keys).
	AddSeries("Occurrences", values)
	// Save to file
	f, _ := os.Create("./output/bar.html")
    bar.Render(f)
}
