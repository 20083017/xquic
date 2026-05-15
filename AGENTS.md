# AGENTS.md

## Project Overview
This project combines ROS2 and WebRTC.
Use GitHub Copilot Agent to make small, safe, reviewable changes while preserving robot-side interfaces, realtime behavior, signaling flow, and media/session lifecycle correctness.

## Primary Goals
- Keep changes minimal and focused
- Preserve existing architecture and public interfaces
- Prefer root-cause fixes over superficial patches
- Avoid unrelated refactors

## Working Rules
- Read relevant ROS2 packages, launch/config files, signaling modules, and media/session code before editing
- Reuse existing patterns already present in the repository
- Do not introduce new dependencies unless necessary
- Do not modify unrelated files or subsystems
- Update docs when behavior, deployment, interfaces, or operator workflow changes

## System Boundary Rules
- Keep ROS2 domain logic separate from WebRTC transport/session logic
- Keep robot control, telemetry, media, and signaling concerns separated
- Do not mix device access, business logic, and transport orchestration in one layer
- Avoid hidden global state between robot sessions, peer sessions, or node lifecycles

## ROS2-Specific Constraints
- Preserve compatibility of:
  - topic names
  - service names
  - action names
  - parameter names
  - QoS assumptions
  - TF frame names
- Do not change launch/runtime assumptions unless explicitly requested
- Handle startup, shutdown, reconnect, and degraded states explicitly
- Be careful with timers, executors, callback groups, and shared resources

## WebRTC-Specific Constraints
- Keep signaling separate from peer connection lifecycle logic
- Keep media track handling separate from application/session orchestration
- Do not silently change SDP, ICE, codec, reconnect, or teardown behavior unless explicitly requested
- Clean up peer connections, data channels, tracks, streams, and listeners correctly
- Preserve signaling message compatibility unless explicitly requested

## Integration Rules
- Treat ROS2 ↔ WebRTC bridging code as a high-risk boundary
- Validate all messages crossing the boundary
- Preserve message ordering, timing expectations, and failure handling
- Avoid blocking ROS2 callbacks with network/media work
- Avoid leaking robot/device/network details through logs or signaling payloads
- Ensure disconnect/reconnect paths leave both ROS2 and WebRTC sides in a recoverable state

## Code Quality
- Keep functions cohesive and easy to read
- Handle errors explicitly
- Validate external input at boundaries
- Avoid hardcoded secrets, machine-specific paths, and environment-specific values
- Prefer immutable updates where practical
- Preserve repository logging style

## Reliability and Safety
- Be conservative when changing:
  - robot control paths
  - telemetry delivery
  - media transport
  - reconnection logic
  - state synchronization
- Preserve safe defaults on failure
- Ensure cleanup logic runs for both node lifecycle and peer/session lifecycle

## Testing and Validation
Before finishing:
- Run existing tests for affected ROS2 and WebRTC modules
- Run existing lint/build/type-check/test commands already present in the repo
- Verify affected ROS2 nodes still start and behave correctly
- Verify affected signaling/media/session flows still behave correctly
- Verify the integration boundary still works as expected
- Do not add new tooling unless required by the task

## Change Workflow
1. Understand the request
2. Inspect affected ROS2, WebRTC, and bridge/integration code
3. Make the smallest complete change
4. Validate with existing commands and the closest relevant runtime path
5. Summarize what changed, interface impact, and operational risks

## When Unsure
- Ask for clarification instead of guessing
- If multiple solutions exist, choose the one most consistent with current boundaries, runtime assumptions, and deployment model