{
  description = "evm_keystore_cli — the headless custodian for keystore_module and signer_manager_module, driven over logosctl.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Pinned to the branches that add Bitcoin wallets, kept phrases and the manager, until they
    # reach main.
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/0e4aa08a9da89a34d17556a2ef0af326b1eccdb1";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/ab2ccfeb2c193dc39bde28c9be9a9c19fdf35ab7";
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
