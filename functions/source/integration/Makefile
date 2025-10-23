PROJECT = LaceworkIntegrationSetup
DIR_NAME = integration
FUNCTION = $(PROJECT)1.1.5
DIST_DIR ?= "$(BASE)"/functions/packages/$(DIR_NAME)
APM_DATASET = $(DATASET)

all: build

.PHONY: clean build

clean:
	rm -rf build
	rm $(DIST_DIR)/$(FUNCTION).zip || true

build: clean
	mkdir -p build
	buildid=$$(git describe --all --long | cut -d "/" -f 2); \
	sed -e "s|\$$BUILD|$$buildid|g" -e "s|\$$DATASET|$(APM_DATASET)|g" lw_integration_lambda_function.py > build/lw_integration_lambda_function.py
	pip3 install -r requirements.txt -t build
	cd build; zip -r $(DIST_DIR)/$(FUNCTION).zip . -x "*.DS_Store*" "*.git*" "build*" "Makefile"
	rm -rf build
