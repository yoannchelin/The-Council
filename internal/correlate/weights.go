package correlate

// Weights controls the contribution of each agent signal to the composite score.
// Tunable without recompile via future -weights flag.
var Weights = struct {
	Blast       float64
	Sentinel    float64
	Hunter      float64
	Dep         float64
	Churn       float64 // archaeo file_commits frequency
	Convergence float64 // multiplier when 3+ signals converge
}{
	Blast:       0.28,
	Sentinel:    0.24,
	Hunter:      0.23,
	Dep:         0.18,
	Churn:       0.07,
	Convergence: 1.50,
}

// ConvergenceThreshold is the minimum number of signals required to apply the convergence bonus.
const ConvergenceThreshold = 3
