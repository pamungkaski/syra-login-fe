import type { NextConfig } from "next";
import webpack from 'webpack'

const nextConfig: NextConfig = {
  /* config options here */
    webpack(config) {
        // 1) Ensure “buffer” imports resolve to the browser polyfill
        config.resolve = {
            ...config.resolve,
            fallback: {
                ...(config.resolve?.fallback ?? {}),
                buffer: require.resolve('buffer/'),
            },
        }

        // 2) Inject a global Buffer constructor into every module
        config.plugins = [
            ...(config.plugins ?? []),
            new webpack.ProvidePlugin({
                Buffer: ['buffer', 'Buffer'],
            }),
        ]

        return config
    },
};

export default nextConfig;
