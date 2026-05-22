package correlate

// Weights controls the contribution of each agent signal to the composite score.
// Values can be tuned without recompile by using the -weights flag (future work).
var Weights = struct {
	Blast     float64
	Sentinel  float64
	Hunter    float64
	Dep       float64
	Convergence float64 // multiplier when 3+ signals converge
}{
	Blast:       0.30,
	Sentinel:    0.25,
	Hunter:      0.25,
	Dep:         0.20,
	Convergence: 1.50,
}

// ConvergenceThreshold is the minimum number of signals required to apply the convergence bonus.
const ConvergenceThreshold = 3
