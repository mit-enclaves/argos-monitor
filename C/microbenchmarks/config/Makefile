all:

# ——————————————————————————— Transition Benchmark ——————————————————————————— #

transition_enclaves:
	sudo ENCLAVES=1 TRANSITION=1 INNER=5000 OUTER=10 ./runbench

transition_sandboxes:
	sudo SANDBOXES=1 TRANSITION=1 INNER=5000 OUTER=10 ./runbench

transition_carves:
	sudo CARVES=1 TRANSITION=1 INNER=5000 OUTER=10 ./runbench

transition_all:
	sudo ENCLAVES=1 SANDBOXES=1 CARVES=1 TRANSITION=1 INNER=5000 OUTER=10 ./runbench

# ———————————— Special benchmark to measure overhead of hardware ————————————— #

hardware_communication:
	sudo INNER=5000 OUTER=10 HWCOMM=1 ./runbench

# ———————————————————————————— Create Benchmarks ————————————————————————————— #

create_enclaves:
	sudo ENCLAVES=1 CREATION=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=1M ./runbench

create_sandboxes:
	sudo SANDBOXES=1 CREATION=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=1M ./runbench

create_carves:
	sudo CARVES=1 CREATION=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=1M ./runbench

create_all:
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=1M ./runbench 

create_enclaves_successive:
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=8k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=16k MAX_SIZE=16k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=32k MAX_SIZE=32k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=64k MAX_SIZE=64k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=128k MAX_SIZE=128k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=256k MAX_SIZE=256k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=512k MAX_SIZE=512k ./runbench 
	sudo CREATION=1 ENCLAVES=1 INNER=10 OUTER=10 MIN_SIZE=1M MAX_SIZE=1M ./runbench 

create_sandboxes_successive:
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=8k ./runbench 
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=16k MAX_SIZE=16k ./runbench 
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=32k MAX_SIZE=32k ./runbench 
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=64k MAX_SIZE=64k ./runbench
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=128k MAX_SIZE=128k ./runbench 
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=256k MAX_SIZE=256k ./runbench 
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=512k MAX_SIZE=512k ./runbench 
	sudo CREATION=1 SANDBOXES=1 INNER=10 OUTER=10 MIN_SIZE=1M MAX_SIZE=1M ./runbench 

create_carves_successive:
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=8k ./runbench 
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=16k MAX_SIZE=16k ./runbench 
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=32k MAX_SIZE=32k ./runbench 
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=64k MAX_SIZE=64k ./runbench
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=128k MAX_SIZE=128k ./runbench 
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=256k MAX_SIZE=256k ./runbench 
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=512k MAX_SIZE=512k ./runbench 
	sudo CREATION=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=1M MAX_SIZE=1M ./runbench 

create_all_successive_size:
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=8k MAX_SIZE=8k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=16k MAX_SIZE=16k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=32k MAX_SIZE=32k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=64k MAX_SIZE=64k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=128k MAX_SIZE=128k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=256k MAX_SIZE=256k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=512k MAX_SIZE=512k ./runbench 
	sudo CREATION=1 ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=10 OUTER=10 MIN_SIZE=1M MAX_SIZE=1M ./runbench 

# —————————————————————————— Attestation Benchmarks —————————————————————————— #

attestation_enclaves:
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=1M ./runbench

attestation_sandboxes:
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=1M ./runbench

attestation_carves:
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=1M ./runbench

attestation_all:
	sudo ENCLAVES=1 SANDBOXES=1 CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=1M ./runbench

attestation_one_enclave:
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=8k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=16k MAX_SIZE=16k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=32k MAX_SIZE=32k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=64k MAX_SIZE=64k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=128k MAX_SIZE=128k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=256k MAX_SIZE=256k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=512k MAX_SIZE=512k ./runbench
	sudo ENCLAVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=1M MAX_SIZE=1M ./runbench

attestation_one_sandbox:
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=8k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=16k MAX_SIZE=16k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=32k MAX_SIZE=32k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=64k MAX_SIZE=64k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=128k MAX_SIZE=128k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=256k MAX_SIZE=256k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=512k MAX_SIZE=512k ./runbench
	sudo SANDBOXES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=1M MAX_SIZE=1M ./runbench

attestation_one_carve:
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=8k MAX_SIZE=8k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=16k MAX_SIZE=16k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=32k MAX_SIZE=32k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=64k MAX_SIZE=64k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=128k MAX_SIZE=128k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=256k MAX_SIZE=256k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=512k MAX_SIZE=512k ./runbench
	sudo CARVES=1 INNER=1000 OUTER=10 ATTESTATION=1 MIN_SIZE=1M MAX_SIZE=1M ./runbench

attestation_per_size_all:
	@make attestation_one_enclave
	@make attestation_one_sandbox
	@make attestation_one_carve

