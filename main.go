package main

import (
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("Hello")
	c := container.NewVBox()

	var bars [8]*widget.ProgressBar
	for i := 0; i <= 7; i += 1 {
		bars[i] = widget.NewProgressBar()
		bars[i].SetValue(float64(i) * 0.1)
		c.Add(bars[i])
	}

	w.SetContent(c)

	w.ShowAndRun()
}
