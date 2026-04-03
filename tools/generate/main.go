package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type templateData struct {
	Name           string
	SnakeCaseName  string
	CamelCaseName  string
	PascalCaseName string
	PackageName    string
}

func newTemplateData(name, dir string) templateData {
	var data templateData

	parts := strings.Split(name, "_")

	snakeCaseParts := []string{}
	camelCaseParts := []string{}
	nameParts := []string{}

	titleCaser := cases.Title(language.English)

	for i, part := range parts {
		snakeCaseParts = append(snakeCaseParts, strings.ToLower(part))
		if i == 0 {
			camelCaseParts = append(camelCaseParts, strings.ToLower(part))
		} else {
			camelCaseParts = append(camelCaseParts, titleCaser.String(part))
		}
		nameParts = append(nameParts, titleCaser.String(part))
	}

	data.Name = strings.Join(nameParts, " ")
	data.PascalCaseName = strings.Join(nameParts, "")
	data.SnakeCaseName = strings.Join(snakeCaseParts, "_")
	data.CamelCaseName = strings.Join(camelCaseParts, "")

	if dir != "" {
		dirParts := strings.Split(dir, "_")
		data.PackageName = strings.Join(dirParts, "")
	} else {
		data.PackageName = strings.Join(snakeCaseParts, "")
	}

	return data
}

func generateFile(tpl *template.Template, filename string, data templateData) error {
	err := os.MkdirAll(filepath.Dir(filename), 0o755)
	if err != nil {
		return fmt.Errorf("error creating directories: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	err = tpl.Execute(file, data)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	fmt.Println("Generated:", filename)
	return nil
}

func generateResource(data templateData, dir string) error {
	tplDir := "./tools/generate"

	goDir := data.SnakeCaseName
	if dir != "" {
		goDir = dir
	}

	tpl, err := template.ParseFiles(filepath.Join(tplDir, "resource.tpl"))
	if err != nil {
		return fmt.Errorf("error loading resource template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./internal/%s/%s.go", goDir, data.SnakeCaseName), data); err != nil {
		return err
	}

	tpl, err = template.ParseFiles(filepath.Join(tplDir, "resource_test.tpl"))
	if err != nil {
		return fmt.Errorf("error loading resource test template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./internal/%s/%s_test.go", goDir, data.SnakeCaseName), data); err != nil {
		return err
	}

	sweepPath := fmt.Sprintf("./internal/%s/sweep.go", goDir)
	if _, err := os.Stat(sweepPath); os.IsNotExist(err) {
		tpl, err = template.ParseFiles(filepath.Join(tplDir, "sweep.tpl"))
		if err != nil {
			return fmt.Errorf("error loading sweep template: %w", err)
		}
		if err := generateFile(tpl, sweepPath, data); err != nil {
			return err
		}
	} else {
		fmt.Printf("Skipped:   %s (already exists)\n", sweepPath)
	}

	tpl, err = template.ParseFiles(filepath.Join(tplDir, "resource_example.tpl"))
	if err != nil {
		return fmt.Errorf("error loading example template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./examples/resources/crowdstrike_%s/resource.tf", data.SnakeCaseName), data); err != nil {
		return err
	}

	tpl, err = template.ParseFiles(filepath.Join(tplDir, "resource_import.tpl"))
	if err != nil {
		return fmt.Errorf("error loading import template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./examples/resources/crowdstrike_%s/import.sh", data.SnakeCaseName), data); err != nil {
		return err
	}

	return nil
}

func generateDataSource(data templateData, dir string) error {
	tplDir := "./tools/generate"

	goDir := data.SnakeCaseName
	if dir != "" {
		goDir = dir
	}

	tpl, err := template.ParseFiles(filepath.Join(tplDir, "datasource.tpl"))
	if err != nil {
		return fmt.Errorf("error loading data source template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./internal/%s/%s_data_source.go", goDir, data.SnakeCaseName), data); err != nil {
		return err
	}

	tpl, err = template.ParseFiles(filepath.Join(tplDir, "datasource_test.tpl"))
	if err != nil {
		return fmt.Errorf("error loading data source test template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./internal/%s/%s_data_source_test.go", goDir, data.SnakeCaseName), data); err != nil {
		return err
	}

	tpl, err = template.ParseFiles(filepath.Join(tplDir, "datasource_example.tpl"))
	if err != nil {
		return fmt.Errorf("error loading data source example template: %w", err)
	}
	if err := generateFile(tpl, fmt.Sprintf("./examples/data-sources/crowdstrike_%s/data-source.tf", data.SnakeCaseName), data); err != nil {
		return err
	}

	return nil
}

func usage() {
	fmt.Println("Usage: go run ./tools/generate <resource|datasource> [flags] <name>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  resource    Generate a new Terraform resource")
	fmt.Println("  datasource  Generate a new Terraform data source")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -d string   Directory under internal/ to place the generated file")
	fmt.Println()
	fmt.Println("The 'crowdstrike_' prefix is automatically stripped if provided.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run ./tools/generate resource host_group")
	fmt.Println("  go run ./tools/generate resource -d cloud_security kac_policy")
	fmt.Println("  go run ./tools/generate datasource -d cloud_security rules")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	command := os.Args[1]
	if command != "resource" && command != "datasource" {
		fmt.Printf("Unknown command: %s\n\n", command)
		usage()
		os.Exit(1)
	}

	fs := flag.NewFlagSet(command, flag.ExitOnError)
	dir := fs.String("d", "", "directory under internal/ to place the generated file")
	fs.Parse(os.Args[2:])

	if fs.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	name := strings.TrimPrefix(fs.Arg(0), "crowdstrike_")
	data := newTemplateData(name, *dir)

	var err error
	switch command {
	case "resource":
		err = generateResource(data, *dir)
	case "datasource":
		err = generateDataSource(data, *dir)
	}

	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
