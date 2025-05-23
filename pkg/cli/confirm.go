package cli

import (
	"fmt"

	"github.com/charmbracelet/huh"
)

const (
	// top level actions
	ActionGet          = "get"
	ActionList         = "list"
	ActionCreate       = "create"
	ActionUpdate       = "update"
	ActionUpdateUnsafe = "unsafely update"
	ActionDeactivate   = "deactivate"
	ActionReactivate   = "reactivate"
	ActionDelete       = "delete"

	// text input names
	InputNameFQN        = "fully qualified name (FQN)"
	InputNameFQNUpdated = "deprecated fully qualified name (FQN) being altered"
)

func ConfirmAction(action, resource, id string, force bool) {
	if force {
		return
	}
	var confirm bool
	err := huh.NewConfirm().
		Title(fmt.Sprintf("Are you sure you want to %s %s:\n\n\t%s", action, resource, id)).
		Affirmative("yes").
		Negative("no").
		Value(&confirm).
		Run()
	if err != nil {
		ExitWithError("Confirmation prompt failed", err)
	}

	if !confirm {
		ExitWithError("Aborted", nil)
	}
}

func ConfirmTextInput(action, resource, inputName, shouldMatchValue string) {
	var input string
	err := huh.NewInput().
		Title(fmt.Sprintf("To confirm you want to %s this %s and accept any side effects, please enter the %s to proceed: %s", action, resource, inputName, shouldMatchValue)).
		Value(&input).
		Validate(func(s string) error {
			if s != shouldMatchValue {
				return fmt.Errorf("entered FQN [%s] does not match required %s: %s", s, inputName, shouldMatchValue)
			}
			return nil
		}).Run()
	if err != nil {
		ExitWithError("Confirmation prompt failed", err)
	}
}

func AskForInput(message string) string {
	var input string
	err := huh.NewInput().
		Value(&input).
		Title(message).
		Run()
	if err != nil {
		ExitWithError("Prompt for input failed", err)
	}
	return input
}

func AskForSecret(message string) string {
	var secret string
	err := huh.NewInput().
		Value(&secret).
		Title(message).
		EchoMode(huh.EchoModePassword).
		Run()
	if err != nil {
		ExitWithError("Prompt for secret failed", err)
	}
	return secret
}

// PromptWithChoices displays a prompt with a list of choices and returns the selected choice.
func PromptWithChoices(title string, choiceStrings []string) (string, error) {
	if len(choiceStrings) == 0 {
		return "", fmt.Errorf("no choices provided to PromptWithChoices")
	}

	options := make([]huh.Option[string], len(choiceStrings))
	for i, choice := range choiceStrings {
		options[i] = huh.NewOption(choice, choice)
	}

	var selectedValue string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(title).
				Options(options...).
				Value(&selectedValue),
		),
	)

	err := form.Run()
	if err != nil {
		// Check if the error is due to user interruption (e.g., Ctrl+C)
		// huh.ErrUserAborted is the typical error for this.
		if err == huh.ErrUserAborted {
			return "", err // Propagate the specific error
		}
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	if selectedValue == "" && len(choiceStrings) > 0 {
		// This case should ideally not happen if huh.Select works as expected
		// and a default is selected or user makes a selection.
		// If there's only one option, huh might auto-select it.
		// If multiple options and no default, user must select one.
		// For safety, if it's empty, and choices were present, consider it an issue.
		// However, if huh.Run() returns nil error, a value should be set.
		// If only one choice, it might be pre-selected.
		if len(choiceStrings) == 1 {
			return choiceStrings[0], nil
		}
		return "", fmt.Errorf("no selection made or prompt issue, though no direct error reported")
	}

	return selectedValue, nil
}
