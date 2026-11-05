{
  description = "evm_keystore_cli — the headless custodian for keystore_module and signer_manager_module, driven over logosctl.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # The heads of keystore#40 (one password per wallet) and manager#18; merge commits once they land.
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/e83a899a1718ed52e3173dc85d06b15b9c68f41a";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/bd5c84d21ced71246c4bf44d137aa1c597496fb0";
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
