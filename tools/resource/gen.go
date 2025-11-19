package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type resource struct {
	Name           string
	SnakeCaseName  string
	CamelCaseName  string
	PascalCaseName string
	PackageName    string
}

func (r resource) generateImport(tpl *template.Template) error {
	filename := fmt.Sprintf("./examples/resources/crowdstrike_%s/import.sh", r.SnakeCaseName)

	err := os.MkdirAll(filepath.Dir(filename), 0o755)
	if err != nil {
		return fmt.Errorf("error creating directories: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	err = tpl.Execute(file, r)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	fmt.Println("Generated:", filename)
	return nil
}

func (r resource) generateExample(tpl *template.Template) error {
	filename := fmt.Sprintf("./examples/resources/crowdstrike_%s/resource.tf", r.SnakeCaseName)

	err := os.MkdirAll(filepath.Dir(filename), 0o755)
	if err != nil {
		return fmt.Errorf("error creating directories: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	err = tpl.Execute(file, r)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	fmt.Println("Generated:", filename)
	return nil
}

func (r resource) generateResource(tpl *template.Template) error {
	filename := fmt.Sprintf("./internal/%s/%s.go", r.SnakeCaseName, r.SnakeCaseName)

	err := os.MkdirAll(filepath.Dir(filename), 0o755)
	if err != nil {
		return fmt.Errorf("error creating directories: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	err = tpl.Execute(file, r)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	fmt.Println("Generated:", filename)
	return nil
}

func newResource(resourceName string) resource {
	var resource resource

	parts := strings.Split(resourceName, "_")

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

	resource.Name = strings.Join(nameParts, " ")
	resource.PascalCaseName = strings.Join(nameParts, "")
	resource.SnakeCaseName = strings.Join(snakeCaseParts, "_")
	resource.CamelCaseName = strings.Join(camelCaseParts, "")
	resource.PackageName = strings.Join(snakeCaseParts, "")

	return resource
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run gen.go <ResourceName> excluding the 'crowdstrike_' prefix")
		os.Exit(1)
	}

	resourceName := os.Args[1]

	resource := newResource(resourceName)

	tplResource, err := template.ParseFiles("./tools/resource/resource.tpl")
	if err != nil {
		fmt.Println("Error loading resource template:", err)
		os.Exit(1)
	}
	if err := resource.generateResource(tplResource); err != nil {
		fmt.Println("Error generating resource:", err)
		os.Exit(1)
	}

	tplExample, err := template.ParseFiles("./tools/resource/example.tpl")
	if err != nil {
		fmt.Println("Error loading example template:", err)
		os.Exit(1)
	}
	if err := resource.generateExample(tplExample); err != nil {
		fmt.Println("Error generating example:", err)
		os.Exit(1)
	}

	tplImport, err := template.ParseFiles("./tools/resource/import.tpl")
	if err != nil {
		fmt.Println("Error loading import template:", err)
		os.Exit(1)
	}
	if err := resource.generateImport(tplImport); err != nil {
		fmt.Println("Error generating import:", err)
		os.Exit(1)
	}
}
