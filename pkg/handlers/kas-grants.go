package handlers

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
)

// NamespaceMappingInfo holds ID and FQN for a namespace mapping.
type NamespaceMappingInfo struct {
	ID  string
	FQN string
}

// AttributeMappingInfo holds ID and FQN for an attribute definition mapping.
type AttributeMappingInfo struct {
	ID  string
	FQN string
}

// ValueMappingInfo holds ID and FQN for an attribute value mapping.
type ValueMappingInfo struct {
	ID  string
	FQN string
}

type KasGrantsMigrationPlan struct {
	KAS                      *policy.KeyAccessServer
	Keys                     []*kasregistry.CreateKeyRequest
	HasRemotePublicKeySource bool // True if the KAS.PublicKey was of type Remote
	NamespaceMappings        []NamespaceMappingInfo
	AttributeMappings        []AttributeMappingInfo
	ValueMappings            []ValueMappingInfo
}

func (h Handler) AssignKasGrantToAttribute(ctx context.Context, attr_id string, kas_id string) (*attributes.AttributeKeyAccessServer, error) {
	kas := &attributes.AttributeKeyAccessServer{
		AttributeId:       attr_id,
		KeyAccessServerId: kas_id,
	}
	resp, err := h.sdk.Attributes.AssignKeyAccessServerToAttribute(ctx, &attributes.AssignKeyAccessServerToAttributeRequest{
		AttributeKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetAttributeKeyAccessServer(), nil
}

func (h Handler) DeleteKasGrantFromAttribute(ctx context.Context, attr_id string, kas_id string) (*attributes.AttributeKeyAccessServer, error) {
	kas := &attributes.AttributeKeyAccessServer{
		AttributeId:       attr_id,
		KeyAccessServerId: kas_id,
	}
	resp, err := h.sdk.Attributes.RemoveKeyAccessServerFromAttribute(ctx, &attributes.RemoveKeyAccessServerFromAttributeRequest{
		AttributeKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetAttributeKeyAccessServer(), nil
}

func (h Handler) AssignKasGrantToValue(ctx context.Context, val_id string, kas_id string) (*attributes.ValueKeyAccessServer, error) {
	kas := &attributes.ValueKeyAccessServer{
		ValueId:           val_id,
		KeyAccessServerId: kas_id,
	}
	resp, err := h.sdk.Attributes.AssignKeyAccessServerToValue(ctx, &attributes.AssignKeyAccessServerToValueRequest{
		ValueKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetValueKeyAccessServer(), nil
}

func (h Handler) DeleteKasGrantFromValue(ctx context.Context, val_id string, kas_id string) (*attributes.ValueKeyAccessServer, error) {
	kas := &attributes.ValueKeyAccessServer{
		ValueId:           val_id,
		KeyAccessServerId: kas_id,
	}
	resp, err := h.sdk.Attributes.RemoveKeyAccessServerFromValue(ctx, &attributes.RemoveKeyAccessServerFromValueRequest{
		ValueKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetValueKeyAccessServer(), nil
}

func (h Handler) AssignKasGrantToNamespace(ctx context.Context, ns_id string, kas_id string) (*namespaces.NamespaceKeyAccessServer, error) {
	kas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       ns_id,
		KeyAccessServerId: kas_id,
	}
	resp, err := h.sdk.Namespaces.AssignKeyAccessServerToNamespace(ctx, &namespaces.AssignKeyAccessServerToNamespaceRequest{
		NamespaceKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetNamespaceKeyAccessServer(), nil
}

func (h Handler) DeleteKasGrantFromNamespace(ctx context.Context, ns_id string, kas_id string) (*namespaces.NamespaceKeyAccessServer, error) {
	kas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       ns_id,
		KeyAccessServerId: kas_id,
	}
	resp, err := h.sdk.Namespaces.RemoveKeyAccessServerFromNamespace(ctx, &namespaces.RemoveKeyAccessServerFromNamespaceRequest{
		NamespaceKeyAccessServer: kas,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetNamespaceKeyAccessServer(), nil
}

func (h Handler) ListKasGrants(ctx context.Context, kas_id, kas_uri string, limit, offset int32) ([]*kasregistry.KeyAccessServerGrants, *policy.PageResponse, error) {
	resp, err := h.sdk.KeyAccessServerRegistry.ListKeyAccessServerGrants(ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasId:  kas_id,
		KasUri: kas_uri,
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	//nolint:staticcheck // deprecated but not removed while public keys work is experimental
	return resp.GetGrants(), resp.GetPagination(), nil
}

func (h Handler) MigrateKasGrants(ctx context.Context) (map[string]KasGrantsMigrationPlan, error) {
	var offset int32 = 0
	const pageSize int32 = 1 // You can adjust the page size as needed

	migrationPlans := make(map[string]KasGrantsMigrationPlan)

	for {
		// Fetch a page of grants
		grants, _, err := h.ListKasGrants(ctx, "", "", pageSize, offset)
		if err != nil {
			return nil, err // Handle error, e.g., by logging and/or returning
		}

		// If no grants are returned, it means we have reached the end
		if len(grants) == 0 {
			break
		}

		// Process the grants from the current page
		for _, grant := range grants {
			migration := KasGrantsMigrationPlan{}

			// Save KeyAccess Server information
			migration.KAS = grant.GetKeyAccessServer()

			// Build Keys List
			switch pkType := grant.GetKeyAccessServer().GetPublicKey().GetPublicKey().(type) {
			case *policy.PublicKey_Cached:
				migration.HasRemotePublicKeySource = false // Explicitly set for clarity
				// Handle cached public keys
				for _, key := range pkType.Cached.GetKeys() {
					key := &kasregistry.CreateKeyRequest{
						KasId:        grant.GetKeyAccessServer().GetId(),
						KeyId:        key.GetKid(),
						KeyAlgorithm: convertKasAlgToAlg(key.GetAlg()),
						KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
						PublicKeyCtx: &policy.KasPublicKeyCtx{
							Pem: base64.StdEncoding.EncodeToString([]byte(key.GetPem())),
						},
					}
					migration.Keys = append(migration.Keys, key)
				}
			case *policy.PublicKey_Remote:
				migration.HasRemotePublicKeySource = true // Set the flag
				// The fmt.Printf line that was here is now removed.
				// The cmd package will handle informing the user.
			}

			// Build Namespace Mappings
			for _, nsGrant := range grant.GetNamespaceGrants() {
				migration.NamespaceMappings = append(migration.NamespaceMappings, NamespaceMappingInfo{
					ID:  nsGrant.GetId(),
					FQN: nsGrant.GetFqn(),
				})
			}

			// Build Attribute Mappings
			for _, attrGrant := range grant.GetAttributeGrants() {
				migration.AttributeMappings = append(migration.AttributeMappings, AttributeMappingInfo{
					ID:  attrGrant.GetId(),
					FQN: attrGrant.GetFqn(),
				})
			}

			// Build Value Mappings
			for _, valGrant := range grant.GetValueGrants() {
				migration.ValueMappings = append(migration.ValueMappings, ValueMappingInfo{
					ID:  valGrant.GetId(),
					FQN: valGrant.GetFqn(),
				})
			}

			// Store the migration plan in the map using the KAS ID as the key
			migrationPlans[grant.GetKeyAccessServer().GetId()] = migration
		}

		// Prepare for the next iteration: increment the offset by the number of grants received
		offset += int32(len(grants))

		// Optional: If the API guarantees that returning fewer items than pageSize means it's the last page,
		// you could add a condition to break early:
		if int32(len(grants)) < pageSize {
			break
		}
		// However, the `len(grants) == 0` check at the beginning of the loop is generally more robust.
	}

	return migrationPlans, nil
}

// CommitKasGrantMigrationForKas performs the actual migration for a single KAS instance
// based on the provided plan and user confirmations.
func (h Handler) CommitKasGrantMigrationForKas(ctx context.Context, originalKasID string, plan KasGrantsMigrationPlan, commitKeys bool, commitMappings bool) error {
	// Skip if HasRemotePublicKeySource is true
	if plan.HasRemotePublicKeySource {
		// This means the KAS has a remote public key source, so we skip the migration.
		// The cmd package will handle informing the user.
		return nil
	}
	// A. Create New Keys
	if commitKeys && len(plan.Keys) > 0 {
		for _, keyReq := range plan.Keys {
			// Ensure the KasId in the key request matches the KAS being processed.
			// This is a sanity check; the plan should already be consistent.
			if keyReq.GetKasId() != originalKasID {
				// This case should ideally not happen if the plan is constructed correctly.
				// Log or handle as a significant inconsistency.
				// For now, we can assume plan.KAS.GetId() is the correct one for the keyReq.
				// Or, more robustly, ensure keyReq.KasId is set to originalKasID if it's different
				// and that's the intended behavior. Given the plan structure, it should be aligned.
				return fmt.Errorf("key request KasId %s does not match original KAS ID %s", keyReq.GetKasId(), originalKasID)
			}
			_, err := h.sdk.KeyAccessServerRegistry.CreateKey(ctx, keyReq)
			if err != nil {
				return fmt.Errorf("failed to create key %s for KAS %s: %w", keyReq.GetKeyId(), originalKasID, err)
			}
		}
	}

	// B. Transition Grants to Key Mappings
	if commitMappings && (len(plan.NamespaceMappings) > 0 || len(plan.AttributeMappings) > 0 || len(plan.ValueMappings) > 0) {
		// Identify Target Key IDs
		targetKeyIDs := []string{}
		if len(plan.Keys) > 0 { // New local keys were created or planned
			for _, key := range plan.Keys {
				targetKeyIDs = append(targetKeyIDs, key.GetKeyId())
			}
		}
		// Note: If plan.HasRemotePublicKeySource is true and len(plan.Keys) == 0,
		// targetKeyIDs will be empty. This means we only unassign old grants.
		// If new keys were created for a remote KAS (e.g. supplementing it), those would be in plan.Keys.

		// Unassign Old Grants (from the original KAS ID)
		for _, nsMap := range plan.NamespaceMappings {
			if _, err := h.DeleteKasGrantFromNamespace(ctx, nsMap.ID, originalKasID); err != nil {
				return fmt.Errorf("failed to unassign KAS grant from namespace %s (FQN: %s) for KAS %s: %w", nsMap.ID, nsMap.FQN, originalKasID, err)
			}
		}
		for _, attrMap := range plan.AttributeMappings {
			if _, err := h.DeleteKasGrantFromAttribute(ctx, attrMap.ID, originalKasID); err != nil {
				return fmt.Errorf("failed to unassign KAS grant from attribute %s (FQN: %s) for KAS %s: %w", attrMap.ID, attrMap.FQN, originalKasID, err)
			}
		}
		for _, valMap := range plan.ValueMappings {
			if _, err := h.DeleteKasGrantFromValue(ctx, valMap.ID, originalKasID); err != nil {
				return fmt.Errorf("failed to unassign KAS grant from value %s (FQN: %s) for KAS %s: %w", valMap.ID, valMap.FQN, originalKasID, err)
			}
		}

		// Assign to New/Target Keys (if targetKeyIDs exist)
		if len(targetKeyIDs) > 0 {
			for _, keyID := range targetKeyIDs {
				for _, nsMap := range plan.NamespaceMappings {
					// We need to use the handler methods that assign a *key* to a namespace/attribute/value
					// The previous search confirmed these:
					// AssignKeyToAttributeNamespace, AssignKeyToAttribute, AssignKeyToAttributeValue
					// These methods are on the respective handlers (NamespaceHandler, AttributeHandler, etc.)
					// which are not directly part of `h Handler` for kas-grants.
					// For now, let's assume direct SDK calls or that these methods will be made available/refactored.
					// Based on current structure, we'd call the specific SDK methods.
					// Let's use the existing handler methods for assigning keys, which were found in the search.
					// These methods are on `h Handler` itself, but might be for different sub-services.
					// Re-checking the search:
					// pkg/handlers/namespaces.go: func (h *Handler) AssignKeyToAttributeNamespace
					// pkg/handlers/attributeValues.go: func (h *Handler) AssignKeyToAttributeValue
					// pkg/handlers/attribute.go: func (h Handler) AssignKeyToAttribute
					// These are methods on the *general* Handler type, so `h.` should work.

					if _, err := h.AssignKeyToAttributeNamespace(ctx, nsMap.ID, keyID); err != nil {
						return fmt.Errorf("failed to assign key %s to namespace %s (FQN: %s): %w", keyID, nsMap.ID, nsMap.FQN, err)
					}
				}
				for _, attrMap := range plan.AttributeMappings {
					if _, err := h.AssignKeyToAttribute(ctx, attrMap.ID, keyID); err != nil {
						return fmt.Errorf("failed to assign key %s to attribute %s (FQN: %s): %w", keyID, attrMap.ID, attrMap.FQN, err)
					}
				}
				for _, valMap := range plan.ValueMappings {
					if _, err := h.AssignKeyToAttributeValue(ctx, valMap.ID, keyID); err != nil {
						return fmt.Errorf("failed to assign key %s to value %s (FQN: %s): %w", keyID, valMap.ID, valMap.FQN, err)
					}
				}
			}
		} else if !plan.HasRemotePublicKeySource && (len(plan.NamespaceMappings) > 0 || len(plan.AttributeMappings) > 0 || len(plan.ValueMappings) > 0) {
			// This case means: grants existed, mappings were confirmed, but no new keys were created AND it's not a remote KAS.
			// This implies the old grants were unassigned, but there are no new keys to assign them to.
			// This situation should be highlighted or logged as it might leave entities without KAS coverage
			// if that was not the intent. The display logic in cmd/kas-grants.go already warns about this.
			// No further action here, just noting the state.
		}
	}
	return nil
}

func convertKasAlgToAlg(alg policy.KasPublicKeyAlgEnum) policy.Algorithm {
	switch alg {
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
		return policy.Algorithm_ALGORITHM_RSA_2048
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:
		return policy.Algorithm_ALGORITHM_RSA_4096
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
		return policy.Algorithm_ALGORITHM_EC_P256
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
		return policy.Algorithm_ALGORITHM_EC_P384
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
		return policy.Algorithm_ALGORITHM_EC_P521
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	}
}
