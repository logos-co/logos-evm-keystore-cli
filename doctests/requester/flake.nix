{
  description = "kcli_probe — doc-test fixture: the app that asks to open a wallet and to unlock it.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Pinned to the commits that made the keystore a signer and added the manager.
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/15c44cc01550ba1b1a92e0a55ef29f17207b818d";
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
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
