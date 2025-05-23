package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort" // Added for sorting KAS IDs

	"github.com/charmbracelet/huh" // Added for styling output
	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	"github.com/google/uuid"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers" // Added for KasGrantsMigrationPlan type
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/spf13/cobra"
)

var forceFlagValue = false

func policy_assignKasGrant(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := NewHandler(c)
	defer h.Close()

	nsID := c.Flags.GetOptionalID("namespace-id")
	attrID := c.Flags.GetOptionalID("attribute-id")
	valID := c.Flags.GetOptionalID("value-id")
	kasID := c.Flags.GetRequiredID("kas-id")

	count := 0
	for _, v := range []string{nsID, attrID, valID} {
		if v != "" {
			count++
		}
	}
	if count != 1 {
		cli.ExitWithError("Must specify exactly one Attribute Namespace ID, Definition ID, or Value ID to assign", errors.New("invalid flag values"))
	}

	var (
		id    string
		res   interface{}
		err   error
		rowID []string
	)

	kas, err := h.GetKasRegistryEntry(kasID)
	if err != nil || kas == nil {
		cli.ExitWithError("Failed to get registered KAS", err)
	}

	ctx := cmd.Context()
	//nolint:gocritic,nestif // this is more readable than a switch statement
	if nsID != "" {
		res, err = h.AssignKasGrantToNamespace(ctx, nsID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to assign KAS Grant for Namespace", err)
		}
		rowID = []string{"Namespace ID", nsID}
	} else if attrID != "" {
		res, err = h.AssignKasGrantToAttribute(ctx, attrID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to assign KAS Grant for Attribute Definition", err)
		}
		rowID = []string{"Attribute ID", attrID}
	} else {
		res, err = h.AssignKasGrantToValue(ctx, valID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to assign KAS Grant for Attribute Value", err)
		}
		rowID = []string{"Value ID", valID}
	}

	t := cli.NewTabular(rowID, []string{"KAS ID", kasID}, []string{"Granted KAS URI", kas.GetUri()})
	HandleSuccess(cmd, id, t, res)
}

func policy_unassignKasGrant(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := NewHandler(c)
	defer h.Close()

	nsID := c.Flags.GetOptionalID("namespace-id")
	attrID := c.Flags.GetOptionalID("attribute-id")
	valID := c.Flags.GetOptionalID("value-id")
	kasID := c.Flags.GetRequiredID("kas-id")
	force := c.Flags.GetOptionalBool("force")

	count := 0
	for _, v := range []string{nsID, attrID, valID} {
		if v != "" {
			count++
		}
	}
	if count != 1 {
		cli.ExitWithError("Must specify exactly one Attribute Namespace ID, Definition ID, or Value ID to unassign", errors.New("invalid flag values"))
	}
	var (
		res     interface{}
		err     error
		confirm string
		rowID   []string
		rowFQN  []string
	)

	kas, err := h.GetKasRegistryEntry(kasID)
	if err != nil || kas == nil {
		cli.ExitWithError("Failed to get registered KAS", err)
	}
	kasURI := kas.GetUri()

	ctx := cmd.Context()
	//nolint:gocritic,nestif // this is more readable than a switch statement
	if nsID != "" {
		ns, err := h.GetNamespace(nsID)
		if err != nil || ns == nil {
			cli.ExitWithError("Failed to get namespace definition", err)
		}
		confirm = fmt.Sprintf("the grant to namespace FQN (%s) of KAS URI", ns.GetFqn())
		cli.ConfirmAction(cli.ActionDelete, confirm, kasURI, force)
		res, err = h.DeleteKasGrantFromNamespace(ctx, nsID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to update KAS grant for namespace", err)
		}

		rowID = []string{"Namespace ID", nsID}
		rowFQN = []string{"Namespace FQN", ns.GetFqn()}
	} else if attrID != "" {
		attr, err := h.GetAttribute(attrID)
		if err != nil || attr == nil {
			cli.ExitWithError("Failed to get attribute definition", err)
		}
		confirm = fmt.Sprintf("the grant to attribute FQN (%s) of KAS URI", attr.GetFqn())
		cli.ConfirmAction(cli.ActionDelete, confirm, kasURI, force)
		res, err = h.DeleteKasGrantFromAttribute(ctx, attrID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to update KAS grant for attribute", err)
		}

		rowID = []string{"Attribute ID", attrID}
		rowFQN = []string{"Attribute FQN", attr.GetFqn()}
	} else {
		val, err := h.GetAttributeValue(valID)
		if err != nil || val == nil {
			cli.ExitWithError("Failed to get attribute value", err)
		}
		confirm = fmt.Sprintf("the grant to attribute value FQN (%s) of KAS URI", val.GetFqn())
		cli.ConfirmAction(cli.ActionDelete, confirm, kasURI, force)
		_, err = h.DeleteKasGrantFromValue(ctx, valID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to update KAS grant for attribute value", err)
		}
		rowID = []string{"Value ID", valID}
		rowFQN = []string{"Value FQN", val.GetFqn()}
	}

	t := cli.NewTabular(rowID, rowFQN,
		[]string{"KAS ID", kasID},
		[]string{"Unassigned Granted KAS URI", kasURI},
	)
	HandleSuccess(cmd, "", t, res)
}

func policy_listKasGrants(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := NewHandler(c)
	defer h.Close()
	kasF := c.Flags.GetOptionalString("kas")
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")
	var (
		kasID  string
		kasURI string
	)

	// if not a UUID, infer flag value passed was a URI
	if kasF != "" {
		_, err := uuid.Parse(kasF)
		if err != nil {
			kasURI = kasF
		} else {
			kasID = kasF
		}
	}

	grants, page, err := h.ListKasGrants(cmd.Context(), kasID, kasURI, limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list assigned KAS Grants", err)
	}

	rows := []table.Row{}
	t := cli.NewTable(
		// columns should be kas id, kas uri, type, id, fqn
		table.NewFlexColumn("kas_id", "KAS ID", cli.FlexColumnWidthThree),
		table.NewFlexColumn("kas_uri", "KAS URI", cli.FlexColumnWidthThree),
		table.NewFlexColumn("grant_type", "Assigned To", cli.FlexColumnWidthOne),
		table.NewFlexColumn("id", "Granted Object ID", cli.FlexColumnWidthThree),
		table.NewFlexColumn("fqn", "Granted Object FQN", cli.FlexColumnWidthThree),
	)

	for _, g := range grants {
		grantedKasID := g.GetKeyAccessServer().GetId()
		grantedKasURI := g.GetKeyAccessServer().GetUri()
		for _, ag := range g.GetAttributeGrants() {
			rows = append(rows, table.NewRow(table.RowData{
				"kas_id":     grantedKasID,
				"kas_uri":    grantedKasURI,
				"grant_type": "Definition",
				"id":         ag.GetId(),
				"fqn":        ag.GetFqn(),
			}))
		}
		for _, vg := range g.GetValueGrants() {
			rows = append(rows, table.NewRow(table.RowData{
				"kas_id":     grantedKasID,
				"kas_uri":    grantedKasURI,
				"grant_type": "Value",
				"id":         vg.GetId(),
				"fqn":        vg.GetFqn(),
			}))
		}
		for _, ng := range g.GetNamespaceGrants() {
			rows = append(rows, table.NewRow(table.RowData{
				"kas_id":     grantedKasID,
				"kas_uri":    grantedKasURI,
				"grant_type": "Namespace",
				"id":         ng.GetId(),
				"fqn":        ng.GetFqn(),
			}))
		}
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, page)

	// Do not supporting printing the 'get --id=...' helper message as grants are atypical
	// with no individual ID.
	cmd.Use = ""
	HandleSuccess(cmd, "", t, grants)
}

// migrationDisplayStyles holds all lipgloss styles for migration output.
type migrationDisplayStyles struct {
	styleTitle     lipgloss.Style
	styleKasID     lipgloss.Style
	styleKasURI    lipgloss.Style
	styleNewKey    lipgloss.Style
	styleFQN       lipgloss.Style
	styleID        lipgloss.Style
	styleWarning   lipgloss.Style
	styleInfo      lipgloss.Style
	styleSeparator lipgloss.Style
	styleAction    lipgloss.Style
	separatorText  string
}

// initMigrationDisplayStyles initializes and returns a migrationDisplayStyles struct.
func initMigrationDisplayStyles() *migrationDisplayStyles {
	return &migrationDisplayStyles{
		styleTitle:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")),
		styleKasID:     lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		styleKasURI:    lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		styleNewKey:    lipgloss.NewStyle().Foreground(lipgloss.Color("13")),
		styleFQN:       lipgloss.NewStyle().Foreground(lipgloss.Color("14")),
		styleID:        lipgloss.NewStyle().Foreground(lipgloss.Color("15")),
		styleWarning:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
		styleInfo:      lipgloss.NewStyle(),
		styleSeparator: lipgloss.NewStyle().Faint(true),
		styleAction:    lipgloss.NewStyle().Foreground(lipgloss.Color("6")),
		separatorText:  "----------------------------------------------------------------------------------------------------",
	}
}
func parseMigrationFlags(cmd *cobra.Command) (interactive bool, commit bool, err error) {
	interactive, err = cmd.Flags().GetBool("interactive")
	if err != nil {
		return false, false, fmt.Errorf("failed to read interactive flag: %w", err)
	}
	commit, err = cmd.Flags().GetBool("commit")
	if err != nil {
		return false, false, fmt.Errorf("failed to read commit flag: %w", err)
	}
	return interactive, commit, nil
}

func policy_migrateKasGrants(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := NewHandler(c)
	defer h.Close()

	interactiveFlag, commitFlag, err := parseMigrationFlags(cmd)
	if err != nil {
		cli.ExitWithError("Failed to parse migration flags", err)
	}

	// Define lipgloss styles (used by displayKasMigrationDetails and potentially others)
	styles := initMigrationDisplayStyles()

	fmt.Println(styles.styleTitle.Render("Building Migration Plan..."))
	fmt.Println()

	plan, err := h.MigrateKasGrants(cmd.Context())
	if err != nil {
		cli.ExitWithError("Failed to create migration plan", err)
	}

	if len(plan) == 0 {
		fmt.Println(styles.styleWarning.Render("No KAS grants found to migrate."))
		HandleSuccess(cmd, "Migration Plan", cli.NewTable(), plan)
		return
	}

	sortedKasIDs := make([]string, 0, len(plan))
	for id := range plan {
		sortedKasIDs = append(sortedKasIDs, id)
	}
	sort.Strings(sortedKasIDs)

	// Helper function to display details for a single KAS migration

	if interactiveFlag {
		runInteractiveKasGrantMigration(cmd, &h, styles, plan, sortedKasIDs, commitFlag)
	} else if commitFlag {
		runBatchKasGrantMigration(cmd, &h, styles, plan, sortedKasIDs)
	} else {
		runPreviewKasGrantMigration(cmd, styles, plan, sortedKasIDs)
	}
}

func init() {
	assignCmd := man.Docs.GetCommand("policy/kas-grants/assign",
		man.WithRun(policy_assignKasGrant),
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("namespace-id").Name,
		assignCmd.GetDocFlag("namespace-id").Shorthand,
		assignCmd.GetDocFlag("namespace-id").Default,
		assignCmd.GetDocFlag("namespace-id").Description,
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("attribute-id").Name,
		assignCmd.GetDocFlag("attribute-id").Shorthand,
		assignCmd.GetDocFlag("attribute-id").Default,
		assignCmd.GetDocFlag("attribute-id").Description,
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("value-id").Name,
		assignCmd.GetDocFlag("value-id").Shorthand,
		assignCmd.GetDocFlag("value-id").Default,
		assignCmd.GetDocFlag("value-id").Description,
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("kas-id").Name,
		assignCmd.GetDocFlag("kas-id").Shorthand,
		assignCmd.GetDocFlag("kas-id").Default,
		assignCmd.GetDocFlag("kas-id").Description,
	)
	injectLabelFlags(&assignCmd.Command, true)

	unassignCmd := man.Docs.GetCommand("policy/kas-grants/unassign",
		man.WithRun(policy_unassignKasGrant),
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("namespace-id").Name,
		unassignCmd.GetDocFlag("namespace-id").Shorthand,
		unassignCmd.GetDocFlag("namespace-id").Default,
		unassignCmd.GetDocFlag("namespace-id").Description,
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("attribute-id").Name,
		unassignCmd.GetDocFlag("attribute-id").Shorthand,
		unassignCmd.GetDocFlag("attribute-id").Default,
		unassignCmd.GetDocFlag("attribute-id").Description,
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("value-id").Name,
		unassignCmd.GetDocFlag("value-id").Shorthand,
		unassignCmd.GetDocFlag("value-id").Default,
		unassignCmd.GetDocFlag("value-id").Description,
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("kas-id").Name,
		unassignCmd.GetDocFlag("kas-id").Shorthand,
		unassignCmd.GetDocFlag("kas-id").Default,
		unassignCmd.GetDocFlag("kas-id").Description,
	)
	unassignCmd.Flags().BoolVar(
		&forceFlagValue,
		unassignCmd.GetDocFlag("force").Name,
		false,
		unassignCmd.GetDocFlag("force").Description,
	)

	listCmd := man.Docs.GetCommand("policy/kas-grants/list",
		man.WithRun(policy_listKasGrants),
	)
	listCmd.Flags().StringP(
		listCmd.GetDocFlag("kas").Name,
		listCmd.GetDocFlag("kas").Shorthand,
		listCmd.GetDocFlag("kas").Default,
		listCmd.GetDocFlag("kas").Description,
	)
	injectListPaginationFlags(listCmd)

	migrateCmd := man.Docs.GetCommand("policy/kas-grants/migrate",
		man.WithRun(policy_migrateKasGrants),
	)

	migrateCmd.Flags().BoolP(
		migrateCmd.GetDocFlag("commit").Name,
		migrateCmd.GetDocFlag("commit").Shorthand,
		migrateCmd.GetDocFlag("commit").DefaultAsBool(),
		migrateCmd.GetDocFlag("commit").Description,
	)

	migrateCmd.Flags().BoolP(
		migrateCmd.GetDocFlag("interactive").Name,
		migrateCmd.GetDocFlag("interactive").Shorthand,
		migrateCmd.GetDocFlag("interactive").DefaultAsBool(),
		migrateCmd.GetDocFlag("interactive").Description,
	)

	cmd := man.Docs.GetCommand("policy/kas-grants",
		man.WithSubcommands(assignCmd, unassignCmd, listCmd, migrateCmd),
	)
	policyCmd.AddCommand(&cmd.Command)
}

// hasNoMappings checks if a KasGrantsMigrationPlan has no mappings to process
func hasNoMappings(migration handlers.KasGrantsMigrationPlan) bool {
	return len(migration.NamespaceMappings) == 0 &&
		len(migration.AttributeMappings) == 0 &&
		len(migration.ValueMappings) == 0
}

// printGrantProcessingHeader prints the header message for grant processing details.
func printGrantProcessingHeader(styles *migrationDisplayStyles, kasIDFromPlan string, migration handlers.KasGrantsMigrationPlan) {
	kasIDStyled := styles.styleKasID.Render(kasIDFromPlan)
	infoRender := styles.styleInfo.Render
	warningRender := styles.styleWarning.Render
	newKeyRender := styles.styleNewKey.Render

	headerPrefix := fmt.Sprintf("  %s %s", infoRender("Existing grants for KAS ID"), kasIDStyled)

	if migration.HasRemotePublicKeySource {
		fmt.Printf("%s (%s):\n",
			headerPrefix,
			warningRender("Remote KAS - grants below will not be migrated"),
		)
	} else if len(migration.Keys) > 0 {
		fmt.Printf("%s %s %s:\n", // Removed one %s as newKeyRender("new key(s)") is one argument
			headerPrefix,
			infoRender("will be transitioned to mappings for these"),
			newKeyRender("new key(s)"),
		)
	} else { // Not remote, and no keys
		fmt.Printf("%s %s\n",
			headerPrefix,
			infoRender("will be processed as follows (note: no new keys are being created for this KAS):"),
		)
	}
	fmt.Println()
}

func displayKasMigrationDetails(styles *migrationDisplayStyles, kasIDFromPlan string, migration handlers.KasGrantsMigrationPlan) {
	kasURIText := ""
	if migration.KAS != nil {
		kasURIText = migration.KAS.GetUri()
	}

	fmt.Println(styles.styleSeparator.Render(styles.separatorText))
	fmt.Printf("%s %s (%s %s)\n",
		styles.styleTitle.Render("Reviewing KAS ID:"),
		styles.styleKasID.Render(kasIDFromPlan),
		styles.styleInfo.Render("URI:"),
		styles.styleKasURI.Render(kasURIText),
	)
	fmt.Println(styles.styleSeparator.Render(styles.separatorText))

	if len(migration.Keys) > 0 {
		fmt.Printf("  %s %s %s (%s):\n",
			styles.styleInfo.Render("The following"),
			styles.styleNewKey.Render("new key(s)"),
			styles.styleInfo.Render("will be created and associated with THIS KAS"),
			styles.styleKasID.Render(kasIDFromPlan),
		)
		for _, key := range migration.Keys {
			fmt.Printf("    %s %s, %s %s\n",
				styles.styleInfo.Render("- New Key ID:"), styles.styleNewKey.Render(key.GetKeyId()),
				styles.styleInfo.Render("Algorithm:"), styles.styleInfo.Render(key.GetKeyAlgorithm().String()),
			)
		}
	} else {
		if migration.HasRemotePublicKeySource {
			fmt.Printf("  %s (%s) %s\n",
				styles.styleWarning.Render("KAS"),
				styles.styleKasID.Render(kasIDFromPlan),
				styles.styleWarning.Render("is configured with a remote public key. Use --interactive to provide the public key."),
			)
		} else {
			fmt.Println(styles.styleInfo.Render("  No new keys will be created for this KAS based on its current configuration (e.g., no cached keys found or no public key defined)."))
		}
	}
	fmt.Println()

	if hasNoMappings(migration) {
		fmt.Println(styles.styleInfo.Render("  No existing grants found for this KAS to transition."))
	} else {
		printGrantProcessingHeader(styles, kasIDFromPlan, migration)

		grantCounter := 1
		for _, nsMap := range migration.NamespaceMappings {
			fmt.Printf("  %s %s %s\n",
				styles.styleInfo.Render(fmt.Sprintf("%d. Original Grant: KAS ID", grantCounter)),
				styles.styleKasID.Render(kasIDFromPlan),
				styles.styleInfo.Render("was granted to Namespace"),
			)
			fmt.Printf("     %s %s (%s %s)\n", styles.styleInfo.Render("FQN:"), styles.styleFQN.Render(nsMap.FQN), styles.styleInfo.Render("ID:"), styles.styleID.Render(nsMap.ID))
			if migration.HasRemotePublicKeySource && len(migration.Keys) == 0 {
				fmt.Println(styles.styleAction.Render("     --> Will be unassigned from this KAS URL."))
				fmt.Println(styles.styleInfo.Render("         (Manual step: Associate specific keys from this remote KAS with the above FQNs if needed, or provide a public key below to create a local key entry.)"))
			} else {
				fmt.Println(styles.styleAction.Render("     --> Will be mapped to:"))
				if len(migration.Keys) > 0 {
					for _, key := range migration.Keys {
						fmt.Printf("         %s %s (%s %s)\n", styles.styleInfo.Render("- New Key ID"), styles.styleNewKey.Render(key.GetKeyId()), styles.styleInfo.Render("associated with KAS ID"), styles.styleKasID.Render(kasIDFromPlan))
					}
				} else {
					fmt.Println(styles.styleWarning.Render("         - (No new keys to map to for this KAS)"))
				}
			}
			fmt.Println()
			grantCounter++
		}
		for _, attrMap := range migration.AttributeMappings {
			fmt.Printf("  %s %s %s\n", styles.styleInfo.Render(fmt.Sprintf("%d. Original Grant: KAS ID", grantCounter)), styles.styleKasID.Render(kasIDFromPlan), styles.styleInfo.Render("was granted to Attribute Definition"))
			fmt.Printf("     %s %s (%s %s)\n", styles.styleInfo.Render("FQN:"), styles.styleFQN.Render(attrMap.FQN), styles.styleInfo.Render("ID:"), styles.styleID.Render(attrMap.ID))
			if migration.HasRemotePublicKeySource && len(migration.Keys) == 0 {
				fmt.Println(styles.styleAction.Render("     --> Will be unassigned from this KAS URL."))
				fmt.Println(styles.styleInfo.Render("         (Manual step: Associate specific keys from this remote KAS with the above FQNs if needed, or provide a public key below to create a local key entry.)"))
			} else {
				fmt.Println(styles.styleAction.Render("     --> Will be mapped to:"))
				if len(migration.Keys) > 0 {
					for _, key := range migration.Keys {
						fmt.Printf("         %s %s (%s %s)\n", styles.styleInfo.Render("- New Key ID"), styles.styleNewKey.Render(key.GetKeyId()), styles.styleInfo.Render("associated with KAS ID"), styles.styleKasID.Render(kasIDFromPlan))
					}
				} else {
					fmt.Println(styles.styleWarning.Render("         - (No new keys to map to for this KAS)"))
				}
			}
			fmt.Println()
			grantCounter++
		}
		for _, valMap := range migration.ValueMappings {
			fmt.Printf("  %s %s %s\n", styles.styleInfo.Render(fmt.Sprintf("%d. Original Grant: KAS ID", grantCounter)), styles.styleKasID.Render(kasIDFromPlan), styles.styleInfo.Render("was granted to Attribute Value"))
			fmt.Printf("     %s %s (%s %s)\n", styles.styleInfo.Render("FQN:"), styles.styleFQN.Render(valMap.FQN), styles.styleInfo.Render("ID:"), styles.styleID.Render(valMap.ID))
			if migration.HasRemotePublicKeySource && len(migration.Keys) == 0 {
				fmt.Println(styles.styleAction.Render("     --> Will be unassigned from this KAS URL."))
				fmt.Println(styles.styleInfo.Render("         (Manual step: Associate specific keys from this remote KAS with the above FQNs if needed, or provide a public key below to create a local key entry.)"))
			} else {
				fmt.Println(styles.styleAction.Render("     --> Will be mapped to:"))
				if len(migration.Keys) > 0 {
					for _, key := range migration.Keys {
						fmt.Printf("         %s %s (%s %s)\n", styles.styleInfo.Render("- New Key ID"), styles.styleNewKey.Render(key.GetKeyId()), styles.styleInfo.Render("associated with KAS ID"), styles.styleKasID.Render(kasIDFromPlan))
					}
				} else {
					fmt.Println(styles.styleWarning.Render("         - (No new keys to map to for this KAS)"))
				}
			}
			fmt.Println()
			grantCounter++
		}
	}
	fmt.Println(styles.styleSeparator.Render(styles.separatorText))
	fmt.Println() // Add a blank line
}

// runInteractiveKasGrantMigration handles the interactive migration flow.
func runInteractiveKasGrantMigration(cmd *cobra.Command, h *handlers.Handler, styles *migrationDisplayStyles, plan map[string]handlers.KasGrantsMigrationPlan, sortedKasIDs []string, commitFlag bool) {
	fmt.Println(styles.styleInfo.Render("Interactive mode selected. Processing KAS instances one by one..."))
	kasProcessed := 0
	kasSuccessfullyCommitted := 0
	kasSkippedByUser := 0
	failedKASCommits := make(map[string]string)
	abortAll := false

	for _, kasIDFromPlan := range sortedKasIDs {
		if abortAll {
			break
		}
		// Get a fresh copy of migration for modification within the loop
		currentMigrationPlan := plan[kasIDFromPlan]
		kasProcessed++

		// Flags to determine what to commit for this KAS
		commitKeysForThisKas := false
		commitMappingsForThisKas := false // Default to false; grants are not touched unless explicitly confirmed

		displayKasMigrationDetails(styles, kasIDFromPlan, currentMigrationPlan)

		// STAGE 1: Determine if keys will be created/used for this KAS
		if currentMigrationPlan.HasRemotePublicKeySource && len(currentMigrationPlan.Keys) == 0 {
			fmt.Println(styles.styleInfo.Render(fmt.Sprintf("KAS ID %s is remote and has no local keys planned.", kasIDFromPlan)))
			promptPublicKeyTitle := fmt.Sprintf("For remote KAS ID %s: Provide a public key to create a local key entry and map grants to it?", styles.styleKasID.Render(kasIDFromPlan))
			var choiceKeyAction string
			keyActionForm := huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[string]().
						Title(promptPublicKeyTitle).
						Options(
							huh.NewOption("Yes, provide public key", "yes-provide-key"),
							huh.NewOption("No, skip key (grants will NOT be unassigned for this KAS)", "no-skip-key"),
							huh.NewOption("Skip all actions for this KAS", "skip-kas"),
							huh.NewOption("Abort entire migration", "abort-all"),
						).
						Value(&choiceKeyAction),
				),
			)
			errKeyActionPrompt := keyActionForm.Run()

			if errKeyActionPrompt != nil {
				if errors.Is(errKeyActionPrompt, huh.ErrUserAborted) {
					fmt.Println(styles.styleWarning.Render("Migration aborted by user."))
					abortAll = true
				} else {
					fmt.Println(styles.styleWarning.Render(fmt.Sprintf("Error during KAS action prompt for %s: %v. Skipping KAS.", kasIDFromPlan, errKeyActionPrompt)))
				}
				kasSkippedByUser++
				continue
			}

			switch choiceKeyAction {
			case "yes-provide-key":
				var publicKeyInputStr string
				// var keyAlgorithmStr = "RSA:2048" // Default algorithm string

				pkInputForm := huh.NewForm(
					huh.NewGroup(
						huh.NewText().
							Title(fmt.Sprintf("Enter public key (PEM format) for KAS ID %s", kasIDFromPlan)).
							Value(&publicKeyInputStr).
							Validate(func(s string) error {
								if s == "" {
									return errors.New("public key cannot be empty")
								}
								// A more thorough PEM validation could be added here
								return nil
							}),
						// Optionally, add a prompt for algorithm if not defaulting:
						// huh.NewInput().Title("Enter key algorithm (e.g., RSA:2048)").Value(&keyAlgorithmStr),
					),
				)
				errPkInput := pkInputForm.Run()

				if errPkInput != nil {
					if errors.Is(errPkInput, huh.ErrUserAborted) {
						fmt.Println(styles.styleWarning.Render(fmt.Sprintf("Public key input cancelled for KAS %s. Treating as 'no-skip-key'.", kasIDFromPlan)))
					} else {
						fmt.Println(styles.styleWarning.Render(fmt.Sprintf("Error during public key input for KAS %s: %v. Treating as 'no-skip-key'.", kasIDFromPlan, errPkInput)))
					}
					commitKeysForThisKas = false
					commitMappingsForThisKas = false // Grants will not be touched
				} else if publicKeyInputStr != "" {
					newKeyID := uuid.NewString()
					// Convert algorithm string to enum, default to RSA2048 for now
					// TODO: Add robust algorithm string parsing and selection if more options are needed
					keyAlgoEnum := policy.Algorithm_ALGORITHM_RSA_2048
					// if keyAlgorithmStr == "EC:SECP256R1" { keyAlgoEnum = policy.Algorithm_ALGORITHM_EC_P256 } // etc.

					newKey := &kasregistry.CreateKeyRequest{
						KasId:        kasIDFromPlan, // Associate with the current KAS
						KeyId:        newKeyID,
						KeyAlgorithm: keyAlgoEnum,
						PublicKeyCtx: &policy.KasPublicKeyCtx{
							Pem: base64.StdEncoding.EncodeToString([]byte(publicKeyInputStr)),
						},
					}
					currentMigrationPlan.Keys = append(currentMigrationPlan.Keys, newKey)
					plan[kasIDFromPlan] = currentMigrationPlan // Update the main plan map
					commitKeysForThisKas = true
					fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Public key provided. New local key %s will be created for KAS ID %s.", newKeyID, kasIDFromPlan)))
					// Re-display details with the new key if desired, or rely on next step's display
					// displayKasMigrationDetails(kasIDFromPlan, currentMigrationPlan)
				} else {
					fmt.Println(styles.styleWarning.Render(fmt.Sprintf("No public key entered for KAS %s. Treating as 'no-skip-key'.", kasIDFromPlan)))
					commitKeysForThisKas = false
					commitMappingsForThisKas = false // Grants will not be touched
				}

			case "no-skip-key":
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping public key provision for KAS ID %s. Existing grants will NOT be unassigned.", kasIDFromPlan)))
				commitKeysForThisKas = false
				commitMappingsForThisKas = false // Critical: ensure grants are not touched
			case "skip-kas":
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping all actions for KAS ID %s.", kasIDFromPlan)))
				kasSkippedByUser++
				continue
			case "abort-all":
				fmt.Println(styles.styleWarning.Render("Aborting entire migration process."))
				abortAll = true
				continue
			}
		} else if len(currentMigrationPlan.Keys) > 0 { // KAS has pre-existing planned keys (e.g., cached, or non-remote with keys)
			promptKeyConfirmTitle := fmt.Sprintf("Create %d new key(s) as planned for KAS ID %s?", len(currentMigrationPlan.Keys), styles.styleKasID.Render(kasIDFromPlan))
			var choiceKeyConfirm string
			keyConfirmForm := huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[string]().
						Title(promptKeyConfirmTitle).
						Options(
							huh.NewOption("Yes, create planned keys", "yes"),
							huh.NewOption("No, do not create these keys", "no"),
							huh.NewOption("Skip all actions for this KAS", "skip-kas"),
							huh.NewOption("Abort entire migration", "abort-all"),
						).
						Value(&choiceKeyConfirm),
				),
			)
			errKeyConfirmPrompt := keyConfirmForm.Run()

			if errKeyConfirmPrompt != nil { /* Similar error/abort handling as above */
				if errors.Is(errKeyConfirmPrompt, huh.ErrUserAborted) {
					fmt.Println(styles.styleWarning.Render("Migration aborted by user."))
					abortAll = true
				} else {
					fmt.Println(styles.styleWarning.Render(fmt.Sprintf("Error during key confirmation for %s: %v. Skipping KAS.", kasIDFromPlan, errKeyConfirmPrompt)))
				}
				kasSkippedByUser++
				continue
			}

			switch choiceKeyConfirm {
			case "yes":
				commitKeysForThisKas = true
			case "no":
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping creation of planned keys for KAS ID %s. Grants will not be transitioned.", kasIDFromPlan)))
				commitKeysForThisKas = false
				commitMappingsForThisKas = false                              // No keys, so no mappings/unassignments
				currentMigrationPlan.Keys = []*kasregistry.CreateKeyRequest{} // Clear keys so grant mapping logic knows
				plan[kasIDFromPlan] = currentMigrationPlan                    // Update plan
			case "skip-kas":
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping all actions for KAS ID %s.", kasIDFromPlan)))
				kasSkippedByUser++
				continue
			case "abort-all":
				fmt.Println(styles.styleWarning.Render("Aborting entire migration process."))
				abortAll = true
				continue
			}
		} else { // No planned keys, and not a remote KAS being prompted for one (e.g., non-remote with no public key defined)
			commitKeysForThisKas = false // No keys to create
			// If there are grants, they cannot be mapped. Per general logic, they shouldn't be unassigned if no keys.
			commitMappingsForThisKas = false
			if len(currentMigrationPlan.NamespaceMappings) > 0 || len(currentMigrationPlan.AttributeMappings) > 0 || len(currentMigrationPlan.ValueMappings) > 0 {
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("KAS ID %s has no local keys planned or provided. Existing grants will not be transitioned or unassigned.", kasIDFromPlan)))
			}
		}

		// STAGE 2: Determine if grant mappings/unassignments will occur
		hasGrantObjectsToMap := len(currentMigrationPlan.NamespaceMappings) > 0 || len(currentMigrationPlan.AttributeMappings) > 0 || len(currentMigrationPlan.ValueMappings) > 0

		if hasGrantObjectsToMap {
			// Only prompt for grant mapping if keys are available and confirmed for creation/use
			if len(currentMigrationPlan.Keys) > 0 && commitKeysForThisKas {
				totalMappings := len(currentMigrationPlan.NamespaceMappings) + len(currentMigrationPlan.AttributeMappings) + len(currentMigrationPlan.ValueMappings)
				promptGrantTransitionTitle := fmt.Sprintf("Transition %d existing grant(s) for KAS ID %s to the associated local key(s)?", totalMappings, styles.styleKasID.Render(kasIDFromPlan))
				var choiceGrantTransition string
				grantTransitionForm := huh.NewForm(
					huh.NewGroup(
						huh.NewSelect[string]().
							Title(promptGrantTransitionTitle).
							Options(
								huh.NewOption("Yes, transition grants", "yes"),
								huh.NewOption("No, do not transition grants (old grants will NOT be unassigned)", "no"), // Clarified consequence
								huh.NewOption("Skip all actions for this KAS", "skip-kas"),
								huh.NewOption("Abort entire migration", "abort-all"),
							).
							Value(&choiceGrantTransition),
					),
				)
				errGrantPrompt := grantTransitionForm.Run()

				if errGrantPrompt != nil { /* Similar error/abort handling */
					if errors.Is(errGrantPrompt, huh.ErrUserAborted) {
						fmt.Println(styles.styleWarning.Render("Migration aborted by user."))
						abortAll = true
					} else {
						fmt.Println(styles.styleWarning.Render(fmt.Sprintf("Error during grant transition prompt for %s: %v. Skipping KAS.", kasIDFromPlan, errGrantPrompt)))
					}
					kasSkippedByUser++
					continue
				}

				switch choiceGrantTransition {
				case "yes":
					commitMappingsForThisKas = true
				case "no":
					fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping grant transition for KAS ID %s. Old grants will not be unassigned.", kasIDFromPlan)))
					commitMappingsForThisKas = false
				case "skip-kas":
					fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping all actions for KAS ID %s.", kasIDFromPlan)))
					kasSkippedByUser++
					continue
				case "abort-all":
					fmt.Println(styles.styleWarning.Render("Aborting entire migration process."))
					abortAll = true
					continue
				}
			} else if len(currentMigrationPlan.Keys) == 0 { // No keys available/confirmed for this KAS.
				// This message might have been shown already in STAGE 1 if no keys were planned/provided.
				// Redundant logging is fine for clarity.
				if currentMigrationPlan.HasRemotePublicKeySource {
					fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Remote KAS %s: No local key was provided/confirmed. Grants will NOT be unassigned.", kasIDFromPlan)))
				} else {
					fmt.Println(styles.styleInfo.Render(fmt.Sprintf("KAS %s: No local keys are available/confirmed. Grants will NOT be transitioned or unassigned.", kasIDFromPlan)))
				}
				commitMappingsForThisKas = false // Ensure this is false
			}
			// If !commitKeysForThisKas but len(currentMigrationPlan.Keys) > 0 (e.g. user said no to creating planned keys),
			// then commitMappingsForThisKas should have been set to false in STAGE 1.
			// The condition `len(currentMigrationPlan.Keys) > 0 && commitKeysForThisKas` correctly gates the prompt.
		} else {
			// No grant objects to map in the first place.
			commitMappingsForThisKas = false // No mapping action needed.
		}

		// STAGE 3: Commit Changes for the Current KAS
		if commitFlag {
			if commitKeysForThisKas || commitMappingsForThisKas {
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Committing changes for KAS ID %s...", kasIDFromPlan)))
				// Pass the potentially modified currentMigrationPlan
				err := h.CommitKasGrantMigrationForKas(cmd.Context(), kasIDFromPlan, currentMigrationPlan, commitKeysForThisKas, commitMappingsForThisKas)
				if err != nil {
					errMsg := fmt.Sprintf("Failed to commit migration for KAS ID %s: %v", kasIDFromPlan, err)
					fmt.Println(styles.styleWarning.Render(errMsg))
					failedKASCommits[kasIDFromPlan] = err.Error()
				} else {
					fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Successfully committed changes for KAS ID %s.", kasIDFromPlan)))
					kasSuccessfullyCommitted++
				}
			} else {
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping commit for KAS ID %s as no actions were confirmed or required.", kasIDFromPlan)))
			}
		} else if commitKeysForThisKas || commitMappingsForThisKas {
			// Not committing, but actions were confirmed.
			fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Preview: Actions for KAS ID %s were confirmed but --commit flag is not set. No changes will be applied.", kasIDFromPlan)))
			if commitKeysForThisKas {
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("  - Keys would be created/updated for KAS ID %s.", kasIDFromPlan)))
			}
			if commitMappingsForThisKas {
				fmt.Println(styles.styleInfo.Render(fmt.Sprintf("  - Grants would be transitioned for KAS ID %s.", kasIDFromPlan)))
			}
		}
	}
	// Print Interactive Summary
	fmt.Println(styles.styleTitle.Render("\nInteractive Migration Summary:"))
	fmt.Printf("  KAS Instances Processed: %d\n", kasProcessed)
	fmt.Printf("  KAS Instances Skipped by User: %d\n", kasSkippedByUser)
	if commitFlag {
		fmt.Printf("  KAS Instances Successfully Committed: %d\n", kasSuccessfullyCommitted)
		fmt.Printf("  KAS Instances Failed to Commit: %d\n", len(failedKASCommits))
		if len(failedKASCommits) > 0 {
			fmt.Println(styles.styleWarning.Render("  Failed KAS Commits:"))
			for id, errMsg := range failedKASCommits {
				fmt.Printf("    - KAS ID %s: %s\n", styles.styleKasID.Render(id), errMsg)
			}
		}
	}
	if abortAll {
		fmt.Println(styles.styleWarning.Render("Migration process was aborted."))
	}
	// HandleSuccess is not used here as summary is custom.
	// Consider if a final raw output is still needed or if summary is enough.
}

// runBatchKasGrantMigration handles the batch commit migration flow.
func runBatchKasGrantMigration(cmd *cobra.Command, h *handlers.Handler, styles *migrationDisplayStyles, plan map[string]handlers.KasGrantsMigrationPlan, sortedKasIDs []string) {
	fmt.Println(styles.styleTitle.Render("\nFull Migration Plan Preview:"))
	for _, kasIDFromPlan := range sortedKasIDs {
		displayKasMigrationDetails(styles, kasIDFromPlan, plan[kasIDFromPlan])
	}
	fmt.Println(styles.styleInfo.Render(fmt.Sprintf("\nProceeding to commit the migration plan for all %d KAS instances...", len(sortedKasIDs))))

	kasSuccessfullyCommitted := 0
	failedKASCommits := make(map[string]string)

	for _, kasIDFromPlan := range sortedKasIDs {
		migration := plan[kasIDFromPlan]
		fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Committing changes for KAS ID %s...", kasIDFromPlan)))
		err := h.CommitKasGrantMigrationForKas(cmd.Context(), kasIDFromPlan, migration, true, true) // Commit all parts
		if err != nil {
			errMsg := fmt.Sprintf("Failed to commit migration for KAS ID %s: %v", kasIDFromPlan, err)
			fmt.Println(styles.styleWarning.Render(errMsg))
			failedKASCommits[kasIDFromPlan] = err.Error()
		} else {
			fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Successfully committed changes for KAS ID %s.", kasIDFromPlan)))
			kasSuccessfullyCommitted++
		}
	}
	// Print Non-Interactive Commit Summary
	fmt.Println(styles.styleTitle.Render("\nNon-Interactive Migration Commit Summary:"))
	fmt.Printf("  Total KAS Instances in Plan: %d\n", len(sortedKasIDs))
	fmt.Printf("  KAS Instances Successfully Committed: %d\n", kasSuccessfullyCommitted)
	fmt.Printf("  KAS Instances Failed to Commit: %d\n", len(failedKASCommits))
	if len(failedKASCommits) > 0 {
		fmt.Println(styles.styleWarning.Render("  Failed KAS Commits:"))
		for id, errMsg := range failedKASCommits {
			fmt.Printf("    - KAS ID %s: %s\n", styles.styleKasID.Render(id), errMsg)
		}
	}
	// HandleSuccess not directly used, custom summary.
}
func runPreviewKasGrantMigration(cmd *cobra.Command, styles *migrationDisplayStyles, plan map[string]handlers.KasGrantsMigrationPlan, sortedKasIDs []string) {
	fmt.Println(styles.styleTitle.Render("\nMigration Plan Preview:"))
	for _, kasIDFromPlan := range sortedKasIDs {
		displayKasMigrationDetails(styles, kasIDFromPlan, plan[kasIDFromPlan])
	}
	HandleSuccess(cmd, "Migration Plan Preview Generated", cli.NewTable(), plan)
}
