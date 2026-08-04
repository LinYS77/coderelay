package outlook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/extractor"
	"github.com/LinYS77/coderelay/internal/version"
)

const (
	graphBaseURL              = "https://graph.microsoft.com/v1.0"
	maxGraphJSONBytes         = 1 << 20
	maxGraphIdentityBytes     = 64 << 10
	maxGraphMessageIDBytes    = 4 << 10
	maxGraphSubjectRunes      = 10_000
	maxGraphPreviewRunes      = 10_000
	maxGraphSeenMessages      = 50
	maxGraphSeenIDBytes       = 128 << 10
	maxGraphListCalls         = 70
	stageOutlookGraphIdentity = "outlook_graph_identity"
	stageOutlookGraphList     = "outlook_graph_list"
	stageOutlookGraphMessage  = "outlook_graph_message"
)

var errGraphMessageGone = errors.New("graph message disappeared")

type graphClient struct {
	baseURL        string
	client         *http.Client
	networkTimeout time.Duration
}

type graphIdentity struct {
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
}

func (i *graphIdentity) Destroy() {
	if i == nil {
		return
	}
	i.Mail = ""
	i.UserPrincipalName = ""
}

type graphEmailAddress struct {
	Address string `json:"address"`
}

type graphRecipient struct {
	EmailAddress graphEmailAddress `json:"emailAddress"`
}

type graphMessageJSON struct {
	ID               string         `json:"id"`
	ReceivedDateTime string         `json:"receivedDateTime"`
	Subject          string         `json:"subject"`
	BodyPreview      string         `json:"bodyPreview"`
	IsRead           bool           `json:"isRead"`
	From             graphRecipient `json:"from"`
}

type graphListResponse struct {
	Value *[]graphMessageJSON `json:"value"`
}

func newGraphClient(baseURL string, client *http.Client, timeout time.Duration) *graphClient {
	return &graphClient{baseURL: strings.TrimRight(baseURL, "/"), client: client, networkTimeout: timeout}
}

func newGraphClientForTest(baseURL string, client *http.Client, timeout time.Duration) *graphClient {
	if client != nil && client.CheckRedirect == nil {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return errors.New("outlook Graph redirects are forbidden")
		}
	}
	return newGraphClient(baseURL, client, timeout)
}

func (p *Provider) resolveGraph(ctx context.Context, source *credential.Secret, notBefore *time.Time, waitSeconds int) ([6]byte, *domain.CredentialUpdate, error) {
	var empty [6]byte
	if p == nil || p.oauth == nil || p.graph == nil || p.extractor == nil || p.now == nil || p.sleep == nil || p.jitter == nil || p.lifecycle == nil || source == nil || ctx == nil || waitSeconds < 0 || waitSeconds > p.maxWait {
		return empty, nil, domain.ErrInvalidCodeRequest
	}
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	select {
	case <-p.lifecycle.Done():
		return empty, nil, domain.ErrUpstreamFailure
	default:
	}
	resolveStart := p.now().UTC()
	pollDeadline := resolveStart.Add(time.Duration(waitSeconds) * time.Second)
	requestCtx, cancelRequest := context.WithCancel(ctx)
	stopLifecycle := context.AfterFunc(p.lifecycle, cancelRequest)
	defer func() {
		stopLifecycle()
		cancelRequest()
	}()
	operationCtx, cancelOperation := context.WithTimeout(requestCtx, outlookAttemptTimeout+time.Duration(waitSeconds)*time.Second)
	defer cancelOperation()

	parsed, err := ParseCredential(source.Bytes())
	if err != nil {
		return empty, nil, domain.ErrInvalidCodeRequest
	}
	defer parsed.Destroy()
	var rotation []byte
	defer func() { clear(rotation) }()
	accessToken, _, err := p.refreshAccessFor(operationCtx, &parsed, &rotation, oauthTargetGraph)
	if err != nil {
		return empty, makeUpdate(rotation), err
	}
	defer func() { clear(accessToken) }()
	identity, err := p.graph.identity(operationCtx, accessToken)
	identityVerified := false
	forceRefreshUsed := false
	refreshAfterRejection := func(refreshCtx context.Context) error {
		if forceRefreshUsed {
			return domain.ErrSourceCredentials
		}
		forceRefreshUsed = true
		clear(accessToken)
		var refreshErr error
		accessToken, _, refreshErr = p.refreshAccessFor(refreshCtx, &parsed, &rotation, oauthTargetGraph)
		if refreshErr != nil {
			return refreshErr
		}
		refreshedIdentity, identityErr := p.graph.identity(refreshCtx, accessToken)
		if identityErr != nil {
			return identityErr
		}
		matched := graphIdentityMatches(parsed.Email, refreshedIdentity)
		refreshedIdentity.Destroy()
		if !matched {
			return domain.WithSourceStage(domain.ErrSourceCredentials, stageOutlookGraphIdentity)
		}
		return nil
	}
	if errors.Is(err, domain.ErrSourceCredentials) {
		err = refreshAfterRejection(operationCtx)
		identityVerified = err == nil
	}
	if err != nil {
		return empty, makeUpdate(rotation), err
	}
	identityMatches := identityVerified || graphIdentityMatches(parsed.Email, identity)
	identity.Destroy()
	if !identityMatches {
		return empty, makeUpdate(rotation), domain.WithSourceStage(domain.ErrSourceCredentials, stageOutlookGraphIdentity)
	}

	seenMessages := make(map[string]struct{}, p.settings.MaxMessages)
	seenIDBytes := 0
	listCalls := 0
	for {
		listCalls++
		if listCalls > maxGraphListCalls {
			return empty, makeUpdate(rotation), domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
		}
		attemptCtx, cancelAttempt := context.WithTimeout(operationCtx, outlookAttemptTimeout)
		messages, listErr := p.graph.listInbox(attemptCtx, accessToken, graphLowerBound(p.now().UTC(), notBefore, p.settings.Extractor.MaxAgeSeconds), p.settings.MaxMessages)
		retryDelay := time.Duration(0)
		if listErr != nil {
			cancelAttempt()
			destroyMessages(messages)
			if errors.Is(listErr, domain.ErrSourceCredentials) && !forceRefreshUsed {
				if refreshErr := refreshAfterRejection(operationCtx); refreshErr != nil {
					return empty, makeUpdate(rotation), refreshErr
				}
				continue
			}
			if ctx.Err() != nil {
				return empty, makeUpdate(rotation), ctx.Err()
			}
			if retrySeconds := domain.RetryAfter(listErr); retrySeconds > 0 {
				retryDelay = time.Duration(retrySeconds) * time.Second
			}
			if waitSeconds == 0 || !p.now().UTC().Before(pollDeadline) || !errors.Is(listErr, domain.ErrUpstreamFailure) && !errors.Is(listErr, domain.ErrSourceRateLimited) {
				return empty, makeUpdate(rotation), listErr
			}
		} else {
			code, extractErr := p.extractGraphMessages(attemptCtx, accessToken, messages, notBefore, p.now().UTC(), seenMessages, &seenIDBytes)
			cancelAttempt()
			destroyMessages(messages)
			if extractErr != nil {
				if errors.Is(extractErr, domain.ErrSourceCredentials) && !forceRefreshUsed {
					if refreshErr := refreshAfterRejection(operationCtx); refreshErr != nil {
						return empty, makeUpdate(rotation), refreshErr
					}
					continue
				}
				if waitSeconds > 0 && p.now().UTC().Before(pollDeadline) && (errors.Is(extractErr, domain.ErrUpstreamFailure) || errors.Is(extractErr, domain.ErrSourceRateLimited)) {
					listErr = extractErr
					if retrySeconds := domain.RetryAfter(extractErr); retrySeconds > 0 {
						retryDelay = time.Duration(retrySeconds) * time.Second
					}
				} else {
					return empty, makeUpdate(rotation), extractErr
				}
			}
			if extractErr == nil && code != "" {
				copy(empty[:], code)
				code = ""
				return empty, makeUpdate(rotation), nil
			}
			if extractErr == nil && waitSeconds == 0 {
				return empty, makeUpdate(rotation), domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
			}
		}

		remaining := pollDeadline.Sub(p.now().UTC())
		if remaining <= 0 {
			return empty, makeUpdate(rotation), domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		delay := p.jitter(duration(p.settings.PollIntervalSeconds))
		if retryDelay > 0 {
			delay = retryDelay
		}
		if delay >= remaining {
			if listErr != nil {
				return empty, makeUpdate(rotation), listErr
			}
			if sleepErr := p.sleep(operationCtx, remaining); sleepErr != nil {
				return empty, makeUpdate(rotation), mapContextError(sleepErr, ctx.Err())
			}
			return empty, makeUpdate(rotation), domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		if sleepErr := p.sleep(operationCtx, delay); sleepErr != nil {
			return empty, makeUpdate(rotation), mapContextError(sleepErr, ctx.Err())
		}
	}
}

func (p *Provider) extractGraphMessages(ctx context.Context, accessToken []byte, messages []extractor.Message, notBefore *time.Time, now time.Time, seen map[string]struct{}, seenIDBytes *int) (string, error) {
	for index := range messages {
		code, err := p.extractor.Extract([]extractor.Message{messages[index]}, notBefore, now)
		if err != nil || code != "" {
			return code, err
		}
		if !strings.HasPrefix(messages[index].ID, "graph:") {
			return "", domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
		}
		rawID := strings.TrimPrefix(messages[index].ID, "graph:")
		if _, alreadySeen := seen[rawID]; alreadySeen {
			continue
		}
		if len(seen) >= maxGraphSeenMessages || seenIDBytes == nil || *seenIDBytes+len(rawID) > maxGraphSeenIDBytes {
			return "", domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
		}
		full, err := p.graph.messageMIME(ctx, accessToken, rawID, messages[index], p.settings.MaxMessageBytes)
		if errors.Is(err, errGraphMessageGone) {
			seen[rawID] = struct{}{}
			*seenIDBytes += len(rawID)
			continue
		}
		if err != nil {
			return "", err
		}
		seen[rawID] = struct{}{}
		*seenIDBytes += len(rawID)
		code, err = p.extractor.Extract([]extractor.Message{full}, notBefore, now)
		full.Destroy()
		if err != nil || code != "" {
			return code, err
		}
	}
	return "", nil
}

func (c *graphClient) identity(ctx context.Context, accessToken []byte) (graphIdentity, error) {
	var result graphIdentity
	endpoint, err := url.Parse(c.baseURL + "/me")
	if err != nil {
		return result, domain.ErrUpstreamFailure
	}
	query := endpoint.Query()
	query.Set("$select", "mail,userPrincipalName")
	endpoint.RawQuery = query.Encode()
	body, err := c.get(ctx, accessToken, endpoint.String(), maxGraphIdentityBytes, stageOutlookGraphIdentity)
	if err != nil {
		return result, err
	}
	defer clear(body)
	if !utf8.Valid(body) || decodeGraphJSON(body, &result) != nil {
		return graphIdentity{}, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphIdentity)
	}
	if utf8.RuneCountInString(result.Mail) > 320 || utf8.RuneCountInString(result.UserPrincipalName) > 320 || result.Mail == "" && result.UserPrincipalName == "" {
		return graphIdentity{}, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphIdentity)
	}
	for _, value := range []string{result.Mail, result.UserPrincipalName} {
		if value == "" {
			continue
		}
		normalized, normalizeErr := normalizeEmail([]byte(value))
		if normalizeErr != nil {
			return graphIdentity{}, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphIdentity)
		}
		clear(normalized)
	}
	return result, nil
}

func (c *graphClient) listInbox(ctx context.Context, accessToken []byte, lower time.Time, maximum int) ([]extractor.Message, error) {
	if maximum < 1 || maximum > 50 {
		return nil, domain.ErrUpstreamFailure
	}
	endpoint, err := url.Parse(c.baseURL + "/me/mailFolders/inbox/messages")
	if err != nil {
		return nil, domain.ErrUpstreamFailure
	}
	query := endpoint.Query()
	query.Set("$select", "id,receivedDateTime,subject,from,bodyPreview,isRead")
	query.Set("$orderby", "receivedDateTime desc")
	query.Set("$filter", "receivedDateTime ge "+lower.UTC().Format(time.RFC3339Nano))
	query.Set("$top", strconv.Itoa(maximum))
	endpoint.RawQuery = query.Encode()
	body, err := c.get(ctx, accessToken, endpoint.String(), maxGraphJSONBytes, stageOutlookGraphList)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if !utf8.Valid(body) {
		return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
	}
	var payload graphListResponse
	if err := decodeGraphJSON(body, &payload); err != nil || payload.Value == nil || len(*payload.Value) > maximum {
		return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
	}
	items := *payload.Value
	defer func() {
		for index := range items {
			items[index] = graphMessageJSON{}
		}
	}()
	messages := make([]extractor.Message, 0, len(items))
	seenIDs := make(map[string]struct{}, len(items))
	for index, item := range items {
		if _, duplicate := seenIDs[item.ID]; duplicate {
			destroyMessages(messages)
			return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
		}
		seenIDs[item.ID] = struct{}{}
		if item.ID == "" || len(item.ID) > maxGraphMessageIDBytes || !utf8.ValidString(item.ID) ||
			utf8.RuneCountInString(item.Subject) > maxGraphSubjectRunes || utf8.RuneCountInString(item.BodyPreview) > maxGraphPreviewRunes ||
			utf8.RuneCountInString(item.From.EmailAddress.Address) > 320 {
			destroyMessages(messages)
			return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
		}
		received, parseErr := time.Parse(time.RFC3339Nano, item.ReceivedDateTime)
		if parseErr != nil {
			destroyMessages(messages)
			return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stageOutlookGraphList)
		}
		messages = append(messages, extractor.Message{
			ID:         "graph:" + item.ID,
			UID:        int64(len(items) - index),
			Subject:    item.Subject,
			Sender:     item.From.EmailAddress.Address,
			ReceivedAt: received.UTC(),
			Preview:    item.BodyPreview,
		})
	}
	sort.SliceStable(messages, func(left, right int) bool {
		if !messages[left].ReceivedAt.Equal(messages[right].ReceivedAt) {
			return messages[left].ReceivedAt.After(messages[right].ReceivedAt)
		}
		return messages[left].UID > messages[right].UID
	})
	return messages, nil
}

func (c *graphClient) messageMIME(ctx context.Context, accessToken []byte, messageID string, metadata extractor.Message, maximum int64) (extractor.Message, error) {
	if c == nil || c.client == nil || ctx == nil || len(accessToken) == 0 || messageID == "" || len(messageID) > maxGraphMessageIDBytes || maximum < 1 {
		return extractor.Message{}, domain.ErrUpstreamFailure
	}
	endpoint := c.baseURL + "/me/mailFolders/inbox/messages/" + url.PathEscape(messageID) + "/$value"
	timeout := c.networkTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return extractor.Message{}, domain.ErrUpstreamFailure
	}
	request.Header.Set("Accept", "message/rfc822, application/octet-stream")
	request.Header.Set("Authorization", "Bearer "+string(accessToken))
	request.Header.Set("User-Agent", "CodeRelay-Outlook/"+version.Value)
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return extractor.Message{}, ctx.Err()
		}
		if requestCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return extractor.Message{}, domain.WithSourceStage(domain.ErrUpstreamTimeout, stageOutlookGraphMessage)
		}
		return extractor.Message{}, domain.WithSourceStage(domain.ErrUpstreamFailure, stageOutlookGraphMessage)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		return extractor.Message{}, errGraphMessageGone
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return extractor.Message{}, mapGraphHTTPError(response.StatusCode, response.Header.Get("Retry-After"), stageOutlookGraphMessage)
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if readErr != nil {
		clear(raw)
		if ctx.Err() != nil {
			return extractor.Message{}, ctx.Err()
		}
		if requestCtx.Err() != nil {
			return extractor.Message{}, domain.WithSourceStage(domain.ErrUpstreamTimeout, stageOutlookGraphMessage)
		}
		return extractor.Message{}, domain.WithSourceStage(domain.ErrUpstreamFailure, stageOutlookGraphMessage)
	}
	partial := int64(len(raw)) > maximum
	if partial {
		raw = raw[:maximum]
	}
	subject, sender, text, html, parseErr := parseMIMEWithPartial(raw, partial)
	clear(raw)
	if parseErr != nil {
		return extractor.Message{}, domain.WithSourceStage(parseErr, stageOutlookGraphMessage)
	}
	if subject == "" {
		subject = metadata.Subject
	}
	if sender == "" {
		sender = metadata.Sender
	}
	return extractor.Message{
		ID:         metadata.ID,
		UID:        metadata.UID,
		Subject:    subject,
		Sender:     sender,
		ReceivedAt: metadata.ReceivedAt,
		Text:       text,
		HTML:       html,
	}, nil
}

func (c *graphClient) get(ctx context.Context, accessToken []byte, endpoint string, maximum int64, stage string) ([]byte, error) {
	if c == nil || c.client == nil || c.baseURL == "" || ctx == nil || len(accessToken) == 0 || maximum < 1 {
		return nil, domain.ErrUpstreamFailure
	}
	timeout := c.networkTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, domain.ErrUpstreamFailure
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(accessToken))
	request.Header.Set("User-Agent", "CodeRelay-Outlook/"+version.Value)
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if requestCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return nil, domain.WithSourceStage(domain.ErrUpstreamTimeout, stage)
		}
		return nil, domain.WithSourceStage(domain.ErrUpstreamFailure, stage)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, mapGraphHTTPError(response.StatusCode, response.Header.Get("Retry-After"), stage)
	}
	if response.ContentLength > maximum {
		return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stage)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if readErr != nil {
		clear(body)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if requestCtx.Err() != nil {
			return nil, domain.WithSourceStage(domain.ErrUpstreamTimeout, stage)
		}
		return nil, domain.WithSourceStage(domain.ErrUpstreamFailure, stage)
	}
	if int64(len(body)) > maximum {
		clear(body)
		return nil, domain.WithSourceStage(domain.ErrUpstreamSchemaChanged, stage)
	}
	return body, nil
}

func decodeGraphJSON(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > maxGraphJSONBytes || !utf8.Valid(raw) {
		return errors.New("graph JSON size or encoding is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeGraphJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("graph JSON contains trailing data")
	}
	return json.Unmarshal(raw, destination)
}

func consumeGraphJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("graph JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		items := 0
		for decoder.More() {
			items++
			if items > 10_000 {
				return errors.New("graph JSON object is too large")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("graph JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("graph JSON contains duplicate key")
			}
			seen[key] = struct{}{}
			if err := consumeGraphJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("graph JSON object is not closed")
		}
		return nil
	case '[':
		items := 0
		for decoder.More() {
			items++
			if items > 10_000 {
				return errors.New("graph JSON array is too large")
			}
			if err := consumeGraphJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("graph JSON array is not closed")
		}
		return nil
	default:
		return errors.New("graph JSON delimiter is invalid")
	}
}

func mapGraphHTTPError(status int, retryAfter, stage string) error {
	var err error
	switch {
	case status == http.StatusUnauthorized:
		err = domain.ErrSourceCredentials
	case status == http.StatusForbidden:
		err = domain.ErrSourceReauthRequired
	case status == http.StatusTooManyRequests:
		err = domain.WithRetryAfter(domain.ErrSourceRateLimited, parseRetryAfterOutlook(retryAfter, 5, time.Now().UTC()))
	case status >= 500:
		err = domain.ErrUpstreamFailure
	default:
		err = domain.ErrUpstreamSchemaChanged
	}
	return domain.WithSourceStage(err, stage)
}

func graphIdentityMatches(email []byte, identity graphIdentity) bool {
	for _, value := range []string{identity.Mail, identity.UserPrincipalName} {
		if value == "" {
			continue
		}
		normalized, err := normalizeEmail([]byte(value))
		if err != nil {
			continue
		}
		matched := bytes.Equal(email, normalized)
		clear(normalized)
		if matched {
			return true
		}
	}
	return false
}

func graphLowerBound(now time.Time, notBefore *time.Time, maxAgeSeconds int) time.Time {
	maxAge := extractor.DefaultMaxAge
	if maxAgeSeconds >= 30 {
		maxAge = time.Duration(maxAgeSeconds) * time.Second
	}
	lower := now.UTC().Add(-maxAge)
	if notBefore != nil && notBefore.UTC().After(lower) {
		lower = notBefore.UTC()
	}
	return lower
}
