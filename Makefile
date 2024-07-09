pdf:
	mkdir -p build
	cp -r media build
	echo \
		"<!doctype html>" \
		"<title>Hierarchical Deterministic Keys for the European Digital Identity Wallet</title>" \
		"<meta charset=utf-8>" \
		> build/hdk.html
	npx -p @mermaid-js/mermaid-cli mmdc -i keys.md -o build/keys.md -e svg -t neutral -w 400
	cat README.md | \
		sed -e "s/# Hierarchical Deterministic Keys for the European Digital Identity Wallet/# Introduction to Hierarchical Deterministic Keys/g" | \
		sed -e "s/keys.md/#hierarchical-deterministic-keys/g" | \
		sed -e "s/prototype.worksheet.sc/https:\/\/github.com\/sander\/hierarchical-deterministic-keys\/blob\/main\/prototype.worksheet.sc/g" | \
		sed -e "s/feedback.md/#feedback-to-enable-hierarchical-deterministic-keys-in-the-wallet-toolbox/g" | \
		pandoc \
		--from=gfm \
		--to=html \
		>> build/hdk.html
	pandoc \
		--from=gfm \
		--to=html \
		build/keys.md \
		>> build/hdk.html
	cat feedback.md | \
		sed -e 's/Hierarchical Deterministic Keys for the European Digital Identity Wallet/Introduction to Hierarchical Deterministic Keys/g' | \
		sed -e 's/README.md/#introduction-to-hierarchical-deterministic-keys/g' | \
		sed -e "s/keys.md/#hierarchical-deterministic-keys/g" | \
		pandoc \
		--from=gfm \
		--to=html \
		>> build/hdk.html
	cd build && \
		cat hdk.html | \
		sed -e "s/<table>/<table><colgroup><col width=16%><col width=42%><col width=42%><\/colgroup>/g" | \
		sed -e "s/<p>Note<\/p>/<p><b>Note<\/b><\/p>/g" | \
		pandoc \
		--from=html \
		--pdf-engine=xelatex \
		--toc \
		--columns=10 \
		--variable title="Hierarchical Deterministic Keys" \
		--variable subtitle="for the European Digital Identity Wallet" \
		--variable date="Version 0.1.0 (2024-07-09)\\\\\vspace{2cm}\href{https://github.com/sander/hierarchical-deterministic-keys}{github.com/sander/hierarchical-deterministic-keys}" \
		--variable colorlinks=true \
		--variable papersize=a4 \
		--variable geometry="margin=2cm" \
		--variable numbersections=true \
		--variable documentclass=report \
		-o hdk.pdf
