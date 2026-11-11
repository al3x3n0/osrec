# Stage presentation

The current authoring source is [.build/explained-stages.mjs](.build/explained-stages.mjs). It exports the eight-slide deck to [output/osrec-stages-explained-final.pptx](output/osrec-stages-explained-final.pptx).

The authoring script requires `@oai/artifact-tool` and the presentation utility paths configured in its header. Its generated render and validation files and local dependency link are ignored by Git.

Final decks, the preview and source images are retained. Superseded draft generators were removed; earlier versions remain available in Git history through commit `bf670da`.
