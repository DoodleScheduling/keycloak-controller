package v1beta1

import (
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ConditionReady                      = "Ready"
	ConditionReconciling                = "Reconciling"
	ConditionInfinispanReady            = "InfinispanReady"
	ConditionKeycloakReady              = "KeycloakReady"
	ConditionWaitingForCanaryInfinispan = "WaitingForCanaryInfinispan"
	ConditionWaitingForCanaryKeycloak   = "WaitingForCanaryKeycloak"
	ConditionCanaryTransitioning        = "CanaryTransitioning"

	ReadyCondition     = "Ready"
	SynchronizedReason = "Synchronized"
	ProgressingReason  = "Progressing"
	FailedReason       = "Failed"
)

// ConditionalResource is a resource with conditions
type conditionalResource interface {
	GetStatusConditions() *[]metav1.Condition
}

// setResourceCondition sets the given condition with the given status,
// reason and message on a resource.
func setResourceCondition(resource conditionalResource, condition string, status metav1.ConditionStatus, reason, message string, generation int64) {
	conditions := resource.GetStatusConditions()

	newCondition := metav1.Condition{
		Type:               condition,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	}

	apimeta.SetStatusCondition(conditions, newCondition)
}
