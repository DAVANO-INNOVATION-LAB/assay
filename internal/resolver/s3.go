package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Resolver fetches artifacts from S3-compatible object storage, which
// covers AWS S3, OpenShift Data Foundation, and MinIO. URI form:
// s3://bucket/prefix
//
// Credentials come from the standard environment (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_S3_ENDPOINT) that the scan job
// projects from the model's connection Secret.
type S3Resolver struct{}

// Scheme implements Resolver.
func (s *S3Resolver) Scheme() string { return "s3" }

// Resolve implements Resolver.
func (s *S3Resolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	u, err := parseURL(uri)
	if err != nil {
		return nil, err
	}
	bucket := u.Host
	prefix := strings.TrimPrefix(u.Path, "/")
	if bucket == "" {
		return nil, fmt.Errorf("s3 URI %q is missing a bucket", uri)
	}

	client, err := newS3Client(ctx)
	if err != nil {
		return nil, err
	}
	downloader := manager.NewDownloader(client)

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}

	var (
		total  int64
		keys   []string
		hasher = sha256.New()
	)

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list s3://%s/%s: %w", bucket, prefix, err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if key == "" || strings.HasSuffix(key, "/") {
				continue
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(key, prefix), "/")
			if rel == "" {
				rel = filepath.Base(key)
			}
			target, err := safeJoin(destDir, rel)
			if err != nil {
				return nil, err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, fmt.Errorf("create staging subdir: %w", err)
			}
			f, err := os.Create(target)
			if err != nil {
				return nil, fmt.Errorf("create %s: %w", target, err)
			}
			n, err := downloader.Download(ctx, f, &s3.GetObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			})
			closeErr := f.Close()
			if err != nil {
				return nil, fmt.Errorf("download s3://%s/%s: %w", bucket, key, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("close %s: %w", target, closeErr)
			}
			total += n
			keys = append(keys, fmt.Sprintf("%s:%s", key, aws.ToString(obj.ETag)))
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no objects found at s3://%s/%s", bucket, prefix)
	}

	// Object storage has no native digest for a multi-object prefix, so the
	// artifact identity is a stable hash over the object keys and ETags.
	sort.Strings(keys)
	for _, k := range keys {
		hasher.Write([]byte(k))
	}

	return &Artifact{
		URI:       uri,
		Digest:    "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		MediaType: "application/vnd.assay.model-prefix",
		LocalPath: destDir,
		SizeBytes: total,
	}, nil
}

func newS3Client(ctx context.Context) (*s3.Client, error) {
	var loadOpts []func(*awsconfig.LoadOptions) error

	if region := firstEnv("AWS_REGION", "AWS_DEFAULT_REGION"); region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(region))
	} else {
		// ODF and MinIO ignore the region but the SDK requires one.
		loadOpts = append(loadOpts, awsconfig.WithRegion("us-east-1"))
	}

	if key, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); key != "" && secret != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(key, secret, os.Getenv("AWS_SESSION_TOKEN")),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	endpoint := firstEnv("AWS_S3_ENDPOINT", "S3_ENDPOINT")
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			if !strings.Contains(endpoint, "://") {
				endpoint = "https://" + endpoint
			}
			o.BaseEndpoint = aws.String(endpoint)
			// Non-AWS S3 implementations generally require path-style access.
			o.UsePathStyle = true
		}
	}), nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
