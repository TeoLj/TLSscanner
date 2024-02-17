package main

import (
	"encoding/csv"
	"fmt"
	"image/color"
	"os"
	"math"
	"strings"
	"sync"
	//"github.com/gonum/plot/vg"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
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
			a.PlotResults(a.SaveResultsDirectory + "/cipherCounts_plot.png", a.cipherCount)
		} else {
			// Create a folder called output to save the results if it doesn't exist
			if _, err := os.Stat("output"); os.IsNotExist(err) {
				os.Mkdir("output", 0755)
			}
			a.SaveCiphersCount("./output/cipherCounts.csv")
			a.PlotResults("./output/cipherCounts_plot.png", a.cipherCount)
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


func (a *Analyzer) PlotResults(outputFile string, cipherCount map[string]int)error {

	p:= plot.New()
	p.Title.Text = "Cipher Suite Occurrences"
	p.X.Label.Text = "Cipher Suite"
	p.Y.Label.Text = "Occurrences"
	
	// Prepare the data for plotting
    var values plotter.Values
    cipherNames := make([]string, len(cipherCount))
    i := 0
    for cipher, count := range cipherCount {
        values = append(values, float64(count))
        // Use an index or shortened version of the cipher suite name
        cipherNames[i] = fmt.Sprintf("%d: %s", i+1, cipher)
        i++
    }

	 // Create the bar chart
	 barChart, err := plotter.NewBarChart(values, vg.Points(20))
	 if err != nil {
		 return err
	 }
	
	// Create a bar plot
	barChart.Color = color.RGBA{R: 0, G: 0, B: 255, A: 255}
    barChart.Offset = vg.Points(0)

    p.Add(barChart)
    p.NominalX(cipherNames...)


	// Set the X-axis tick label rotation and alignment
	p.X.Tick.Label.Rotation = math.Pi / 4 // 45 degrees
	p.X.Tick.Label.XAlign = draw.XRight

	// Save the plot to a PNG file
    if err := p.Save(8*vg.Inch, 4*vg.Inch, outputFile); err != nil {
        return err
    }


    return nil

}