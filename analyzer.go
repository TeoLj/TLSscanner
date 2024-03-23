package main

import (
	"encoding/csv"
	"fmt"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/components"
	"os"
	"strconv"
	"strings"
	"sync"
	"io"
)

type Analyzer struct {
	ScannedCiphers       []string
	CSVFilePath          string
	ScanAndSaveDirectory string
	DomainsList          string
	cipherCount          map[string]int
	Mutex                *sync.Mutex // fine grained locking
	ErrorCounts          ErrorCounter
}

func NewAnalyzer(scanner Scanner) *Analyzer {
	return &Analyzer{
		ScannedCiphers:       scanner.ScannedCiphers,
		ScanAndSaveDirectory: scanner.opts.ScanAndSaveDirectory,
		CSVFilePath:          scanner.opts.CSVFilePath,
		DomainsList:          scanner.opts.DomainsList,
		cipherCount:          make(map[string]int),
		Mutex:                &sync.Mutex{},
		ErrorCounts:          scanner.ErrorCounts,

	}
}

func (a *Analyzer) Run() {

	a.CountCiphers()
	fileName := strings.TrimSuffix(strings.TrimPrefix(a.CSVFilePath, "./"), ".csv")
	outputDir := "./output"

	if a.ScanAndSaveDirectory != "" {
		os.Chdir(a.ScanAndSaveDirectory)
		outputDir = a.ScanAndSaveDirectory
	}

	if a.DomainsList != "" {
		a.SaveCiphersCount(outputDir + "/cipherCounts.csv")
		a.PlotCipherCountsFromCSV(outputDir + "/cipherCounts.csv")
		a.CombineCharts(outputDir + "/cipherCounts.csv", outputDir + "/plot.html", a.ErrorCounts)
	}

	if a.CSVFilePath != "" {
		a.SaveCiphersCount(outputDir + "/" + fileName + "_cipherCounts.csv")
		a.PlotCipherCountsFromCSV(outputDir + "/" + fileName + "_cipherCounts.csv")
		a.CombineCharts(outputDir + "/" + fileName + "_cipherCounts.csv", outputDir + "/" + fileName + "_plot.html", a.ErrorCounts)
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


func (a *Analyzer) PlotCipherCountsFromCSV(filenameIn string) *charts.Bar {
	// Open the CSV file
	file, err := os.Open(filenameIn)

	if err != nil {
		fmt.Println("Error opening CSV file:", err)
		
	}
	defer file.Close()

	// Read the CSV records
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV file:", err)
		
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
					Lang:  []string{ "Data View","Close", "Refresh"},
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
				Show:         true,
				Interval:     "auto",
				Rotate:       60,
				Formatter:    "{value}",
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
				BarGap:         "0%",  // No gap between bars of different categories
				BarCategoryGap: "40%", // Gap between bars of the same category (thinner)
			}),
		)

	bar.SetXAxis(keys).
		SetSeriesOptions(charts.WithMarkLineNameTypeItemOpts(
			opts.MarkLineNameTypeItem{Name: "Maximum", Type: "max"},
			opts.MarkLineNameTypeItem{Name: "Minimum", Type: "min"},
		))

	return bar
}


func (a *Analyzer) PlotErrorCountsToPieChart(errorCounts ErrorCounter) *charts.Pie {
    
	pie := charts.NewPie()

    // Calculate the total count of all errors
    totalErrors := errorCounts.HandshakeFailures +  errorCounts.NoHostFound
    for _, count := range errorCounts.OtherErrors {
        totalErrors += count
    }

    // If totalErrors is 0, avoid division by zero in percentage calculation
    if totalErrors == 0 {
        totalErrors = 1 // Ensure we show 0% for all categories to maintain the full legend
    }

    // Prepare data with label, count, and percentage
    var data []opts.PieData
    addDataPoint := func(name string, count int) {
        percentage := float64(count) / float64(totalErrors) * 100
        label := fmt.Sprintf("%s: %d (%.2f%%)", name, count, percentage)
        data = append(data, opts.PieData{Name: label, Value: count})
    }

    // Add predefined error types
    addDataPoint("Handshake Failures", errorCounts.HandshakeFailures)


	if errorCounts.NoHostFound > 0 {
    addDataPoint("No Such Host", errorCounts.NoHostFound)
	}

    // Add other errors
    for err, count := range errorCounts.OtherErrors {
        addDataPoint(err, count)
    }

    pie.AddSeries("Error Counts", data).
        SetGlobalOptions(
            charts.WithTitleOpts(opts.Title{Title: "Scan Error Report"}),
            charts.WithLegendOpts(opts.Legend{
				Show: true, 
				Right: "right",
				Left: "left",
		        Orient: "horizontal",
				Top: "10%",  
			}),
		). // Add a comma here
		SetSeriesOptions(
			charts.WithPieChartOpts(opts.PieChart{
				Radius:140,
				Center: []string{"50%", "60%"}, // second% is vertical position
			}),
		)
		
			

	pie.SetGlobalOptions(
		// Set the toolbox options
		charts.WithToolboxOpts(opts.Toolbox{
			Show: true,
			Feature: &opts.ToolBoxFeature{
				SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{
					Show:  true,
					Title: "Save as Image",
					Name:  "Error Counts",
					Type:  "png",
				},
				DataView: &opts.ToolBoxFeatureDataView{
					Show:  true,
					Title: "Data View",
					Lang:  []string{"Data View", "Close", "Refresh"},
				},
			},
		}),
	)
	return pie
}

func SetSeriesOptions(seriesOpts charts.SeriesOpts) {
	panic("unimplemented")
}




func (a *Analyzer) CombineCharts(filenameIn, filenameOut string, errorCounts ErrorCounter) {
    page := components.NewPage()

    bar := a.PlotCipherCountsFromCSV(filenameIn) 
    pie := a.PlotErrorCountsToPieChart(errorCounts) // Now returns *charts.Pie

    page.AddCharts(bar, pie)

    // Render the page to the specified output file
    f, err := os.Create(filenameOut)
    if err != nil {
        fmt.Println("Failed to create file:", err)
        return
    }
    defer f.Close()

    if err := page.Render(io.MultiWriter(f)); err != nil {
        fmt.Println("Failed to render page:", err)
    }
}