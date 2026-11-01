{
  description = "evm_keystore_cli — the headless custodian for keystore_module and signer_manager_module, driven over logosctl.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Pinned commits on main: the keystore at the move of an older build's keystore into v2.
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/6ab1d08dfc45d0a472d156cf255bd47d79763a5b";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/48c106c702446a99c529b1febfcdedf1261e7407";
      inputs.logos-module-builder.follows = "logos-module-builder";
      inputs.keystore_module.follows = "keystore_module";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross PSEUDO-SYSTEM the builder understands; a target, never a
      # host nixpkgs is evaluated for natively, so it only ever belongs in `packages`.
      targets = systems ++ [ "x86_64-windows" ];
    in
    {
      packages = nixpkgs.lib.genAttrs targets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
