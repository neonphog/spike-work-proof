use std::sync::{Arc, Mutex};

struct State {
    start: std::time::Instant,
    iterations: Vec<f64>,
    nines: [usize; 5],
}

impl State {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            start: std::time::Instant::now(),
            iterations: Vec::new(),
            nines: [0, 0, 0, 0, 0],
        }))
    }

    pub fn record(&mut self, dur_dif: impl Iterator<Item = (f64, f64)>) {
        for (dur, dif) in dur_dif {
            self.iterations.push(dur);
            if dif >= 1.0 {
                self.nines[0] += 1;
            }
            if dif >= 2.0 {
                self.nines[1] += 1;
            }
            if dif >= 3.0 {
                self.nines[2] += 1;
            }
            if dif >= 4.0 {
                self.nines[3] += 1;
            }
            if dif >= 5.0 {
                self.nines[4] += 1;
            }
        }
    }

    pub fn print(&mut self) -> String {
        let cnt = self.iterations.len() as f64;
        let avg = self.iterations.iter().sum::<f64>() / cnt;
        let out = format!(
            "{:0.01}s: {cnt} in 5 seconds: avg {:0.04}s, nines: {:?}",
            self.start.elapsed().as_secs_f64(),
            avg,
            &self.nines,
        );
        self.iterations.clear();
        out
    }
}

pub fn main() {
    println!("(multithread) timing every 5 seconds:");

    let state = State::new();

    let generators = spike_work_proof::WorkProof::init(
        std::cmp::max(3, num_cpus::get()) - 2,
        &[0xdb; 20],
        &[0xdb; 32],
    )
    .unwrap();

    for mut iter in generators {
        let state = state.clone();
        std::thread::spawn(move || {
            let mut dur_dif = Vec::new();
            loop {
                for _ in 0..10 {
                    let start = std::time::Instant::now();
                    let dif = iter.next().unwrap();
                    let dur = start.elapsed().as_secs_f64();
                    dur_dif.push((dur, dif));
                }
                state.lock().unwrap().record(dur_dif.drain(..));
            }
        });
    }

    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));

        let line = state.lock().unwrap().print();
        println!("{line}");
    }
}
